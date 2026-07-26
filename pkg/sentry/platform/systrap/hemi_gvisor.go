// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package systrap

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/hostsyscall"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

const hemiGvisorDevicePath = "/dev/hemi_userspace"

const hemiGvisorUserMemMax = 16 * hostarch.PageSize

const (
	hemiGvisorRingLaneCount        = 4
	hemiGvisorRingEntries          = linux.HEMI_USERSPACE_RING_ENTRIES
	hemiGvisorRingDescriptorOffset = linux.HEMI_USERSPACE_RING_DESCRIPTOR_OFFSET
	hemiGvisorRingDescriptorSize   = linux.HEMI_USERSPACE_RING_DESCRIPTOR_SIZE
	hemiGvisorRingDataOffset       = linux.HEMI_USERSPACE_RING_DATA_OFFSET
	hemiGvisorRingDataStride       = linux.HEMI_USERSPACE_RING_DATA_STRIDE
	hemiGvisorRingSlotBytes        = hemiGvisorRingDataStride
	hemiGvisorRingMapSize          = linux.HEMI_USERSPACE_RING_MMAP_SIZE
	hemiGvisorRingBatchBytes       = linux.HEMI_USERSPACE_RING_MAX_BYTES
	// Small portal operations are cheaper through the legacy ioctl, which
	// avoids ring lane acquisition and descriptor validation. This threshold
	// keeps syscall metadata and futex-adjacent copies off the batching path.
	hemiGvisorRingMinBytes = 256
)

var hemiGvisorZeroBuffer [hemiGvisorRingBatchBytes]byte

var (
	_ platform.AddressSpaceInitializer       = (*subprocess)(nil)
	_ platform.AddressSpaceForker            = (*subprocess)(nil)
	_ platform.AddressSpaceFilePager         = (*subprocess)(nil)
	_ platform.AddressSpaceIOIter            = (*subprocess)(nil)
	_ platform.AddressSpacePrivateFileMapper = (*subprocess)(nil)
)

type hemiGvisorRingEnterFunc func(int32, *linux.HemiUserspaceRingEnter) unix.Errno

// hemiGvisorRingEnterError reports an ENTER ioctl rejected before the kernel
// processed any descriptor in the submitted batch. Previously completed
// batches remain reflected in the progress returned alongside this error.
type hemiGvisorRingEnterError struct {
	errno unix.Errno
}

func (e *hemiGvisorRingEnterError) Error() string {
	return fmt.Sprintf("HEMI gVisor ring enter: %v", e.errno)
}

func (e *hemiGvisorRingEnterError) Unwrap() error {
	return e.errno
}

type hemiGvisorRingLane struct {
	ringID  uint64
	mapping []byte
}

type hemiGvisorDeviceState struct {
	file *fd.FD
	fd   int32

	mmidMu   sync.Mutex
	nextMMID uint64
	lanes    chan *hemiGvisorRingLane

	tokenMu   sync.Mutex
	nextToken uint64
	tokens    map[uint64]hemiGvisorToken
}

type hemiGvisorToken struct {
	kind      uint32
	mappable  memmap.Mappable
	identity  memmap.MappingIdentity
	file      memmap.File
	fileRange memmap.FileRange
	block     safemem.Block
	mapping   []byte
	refs      uint64
}

func (d *hemiGvisorDeviceState) allocateMMID() (uint64, error) {
	d.mmidMu.Lock()
	defer d.mmidMu.Unlock()
	if d.nextMMID == ^uint64(0) {
		return 0, fmt.Errorf("HEMI gVisor MMID space exhausted")
	}
	d.nextMMID++
	return d.nextMMID, nil
}

var hemiGvisorDevice = struct {
	sync.Mutex
	state *hemiGvisorDeviceState
}{}

func hemiGvisorOpenDevice(devicePath string) (*fd.FD, error) {
	if devicePath == "" {
		devicePath = hemiGvisorDevicePath
	}
	f, err := fd.Open(devicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) {
			return nil, nil
		}
		return nil, fmt.Errorf("opening HEMI gVisor device file (%s): %w", devicePath, err)
	}
	return f, nil
}

func hemiGvisorSetDeviceFD(deviceFile *fd.FD) {
	if deviceFile == nil {
		return
	}
	init := linux.HemiUserspaceInit{
		ABIVersion: linux.HEMI_USERSPACE_ABI_VERSION,
		Route:      linux.HEMI_USERSPACE_ROUTE_SUD,
		Flags: linux.HEMI_USERSPACE_INIT_ANON_DATA |
			linux.HEMI_USERSPACE_INIT_FILE_PRIVATE,
	}
	deviceFD := int32(deviceFile.FD())
	if errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(deviceFD), uintptr(linux.HEMI_USERSPACE_INIT_SESSION),
		uintptr(unsafe.Pointer(&init)), 0, 0, 0); errno != 0 {
		log.Warningf("HEMI userspace session initialization failed; disabling HEMI: %v", errno)
		return
	}
	state := &hemiGvisorDeviceState{
		file:   deviceFile,
		fd:     deviceFD,
		tokens: make(map[uint64]hemiGvisorToken),
	}
	state.lanes = hemiGvisorSetupRingLanes(state.fd)

	hemiGvisorDevice.Lock()
	hemiGvisorDevice.state = state
	hemiGvisorDevice.Unlock()
	go state.drainReleaseLoop()
}

func (d *hemiGvisorDeviceState) drainReleaseLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if err := d.drainReleases(context.Background()); err != nil {
			log.Warningf("HEMI gVisor periodic release drain failed: %v", err)
		}
	}
}

func hemiGvisorCurrentDevice() *hemiGvisorDeviceState {
	hemiGvisorDevice.Lock()
	defer hemiGvisorDevice.Unlock()
	return hemiGvisorDevice.state
}

func hemiGvisorSetupRingLanes(deviceFD int32) chan *hemiGvisorRingLane {
	lanes := make([]*hemiGvisorRingLane, 0, hemiGvisorRingLaneCount)
	for range hemiGvisorRingLaneCount {
		lane, err := hemiGvisorSetupRingLane(deviceFD)
		if err != nil {
			for _, lane := range lanes {
				_ = memutil.UnmapSlice(lane.mapping)
			}
			return nil
		}
		lanes = append(lanes, lane)
	}

	available := make(chan *hemiGvisorRingLane, len(lanes))
	for _, lane := range lanes {
		available <- lane
	}
	return available
}

func hemiGvisorSetupRingLane(deviceFD int32) (*hemiGvisorRingLane, error) {
	setup := linux.HemiUserspaceRingSetup{}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(deviceFD), uintptr(linux.HEMI_USERSPACE_SETUP_RING),
		uintptr(unsafe.Pointer(&setup)), 0, 0, 0)
	if errno != 0 {
		return nil, errno
	}
	if setup.RingID == 0 ||
		setup.MmapOffset%uint64(hostarch.PageSize) != 0 ||
		uint64(uintptr(setup.MmapOffset)) != setup.MmapOffset {
		return nil, fmt.Errorf("invalid HEMI userspace ring setup: %+v", setup)
	}

	mapping, err := memutil.MapSlice(
		0, uintptr(hemiGvisorRingMapSize), unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED, uintptr(uint32(deviceFD)), uintptr(setup.MmapOffset))
	if err != nil {
		return nil, err
	}
	return &hemiGvisorRingLane{ringID: setup.RingID, mapping: mapping}, nil
}

func hemiGvisorRawRingEnter(deviceFD int32, enter *linux.HemiUserspaceRingEnter) unix.Errno {
	return hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(deviceFD), uintptr(linux.HEMI_USERSPACE_ENTER_RING),
		uintptr(unsafe.Pointer(enter)), 0, 0, 0)
}

func (l *hemiGvisorRingLane) descriptor(index int) *linux.HemiUserspaceRingDescriptor {
	offset := hemiGvisorRingDescriptorOffset + index*hemiGvisorRingDescriptorSize
	return (*linux.HemiUserspaceRingDescriptor)(unsafe.Pointer(&l.mapping[offset]))
}

func (l *hemiGvisorRingLane) data(index, length int) []byte {
	offset := hemiGvisorRingDataOffset + index*hemiGvisorRingDataStride
	return l.mapping[offset : offset+length]
}

func (l *hemiGvisorRingLane) transfer(deviceFD int32, mmid uint64, addr hostarch.Addr, data []byte, op uint16, enterFn hemiGvisorRingEnterFunc) (int, error) {
	return l.transferData(deviceFD, mmid, addr, data, op, true, enterFn)
}

// transferInPlace transfers data already stored in, or to be consumed directly
// from, the lane's shared data area. Keeping the platform bounce buffer as the
// safemem Reader/Writer buffer avoids copying through a second Go slice.
func (l *hemiGvisorRingLane) transferInPlace(deviceFD int32, mmid uint64, addr hostarch.Addr, data []byte, op uint16, enterFn hemiGvisorRingEnterFunc) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if len(data) > hemiGvisorRingBatchBytes || &data[0] != &l.mapping[hemiGvisorRingDataOffset] {
		return 0, fmt.Errorf("HEMI gVisor in-place ring transfer received a non-lane buffer")
	}
	return l.transferData(deviceFD, mmid, addr, data, op, false, enterFn)
}

func (l *hemiGvisorRingLane) transferData(deviceFD int32, mmid uint64, addr hostarch.Addr, data []byte, op uint16, bounce bool, enterFn hemiGvisorRingEnterFunc) (int, error) {
	var done int
	for done < len(data) {
		batchLen := min(len(data)-done, hemiGvisorRingBatchBytes)
		count := (batchLen + hemiGvisorRingSlotBytes - 1) / hemiGvisorRingSlotBytes
		batchAddr := addr + hostarch.Addr(done)

		var described int
		for i := 0; i < count; i++ {
			length := min(batchLen-described, hemiGvisorRingSlotBytes)
			*l.descriptor(i) = linux.HemiUserspaceRingDescriptor{
				Addr: uint64(batchAddr + hostarch.Addr(described)),
				Len:  uint32(length),
				Op:   op,
			}
			if bounce && op == linux.HEMI_USERSPACE_RING_OP_WRITE {
				copy(l.data(i, length), data[done+described:done+described+length])
			}
			described += length
		}

		enter := linux.HemiUserspaceRingEnter{
			RingID: l.ringID,
			MMID:   mmid,
			Count:  uint32(count),
		}
		if errno := enterFn(deviceFD, &enter); errno != 0 {
			// The ENTER ABI guarantees that an ioctl error is returned before
			// processing this batch, so callers may retry only its suffix via
			// the legacy portal.
			return done, &hemiGvisorRingEnterError{errno: errno}
		}

		var completed int
		for i := 0; i < count; i++ {
			length := min(batchLen-completed, hemiGvisorRingSlotBytes)
			descriptor := l.descriptor(i)
			expectedAddr := batchAddr + hostarch.Addr(completed)
			if descriptor.Addr != uint64(expectedAddr) || descriptor.Len != uint32(length) ||
				descriptor.Op != op || descriptor.Flags != 0 || descriptor.Done > uint32(length) ||
				descriptor.Result > 0 || descriptor.Reserved != [5]uint64{} {
				return done + completed, fmt.Errorf("HEMI gVisor ring returned an invalid descriptor %d: %+v", i, *descriptor)
			}
			n, err := hemiGvisorUserMemResult(expectedAddr, length, uint64(descriptor.Done), descriptor.Result)
			if bounce && op == linux.HEMI_USERSPACE_RING_OP_READ && n != 0 {
				copy(data[done+completed:done+completed+n], l.data(i, n))
			}
			completed += n
			if err != nil {
				return done + completed, err
			}
		}
		done += completed
	}
	return done, nil
}

func hemiGvisorUseRing(length int) bool {
	return length >= hemiGvisorRingMinBytes
}

func (d *hemiGvisorDeviceState) tryRingTransfer(mmid uint64, addr hostarch.Addr, data []byte, op uint16) (int, error, bool) {
	if d == nil || d.lanes == nil || !hemiGvisorUseRing(len(data)) {
		return 0, nil, false
	}
	select {
	case lane := <-d.lanes:
		n, err := lane.transfer(d.fd, mmid, addr, data, op, hemiGvisorRawRingEnter)
		d.lanes <- lane
		return n, err, true
	default:
		return 0, nil, false
	}
}

// hemiGvisorPrepareAddressSpace records the unbound Host subprocess selected
// for this AddressSpace. HEMI state is created later by either
// InitializeAddressSpace or ForkAddressSpaceFrom.
func (s *subprocess) hemiGvisorPrepareAddressSpace() error {
	device := hemiGvisorCurrentDevice()
	if device == nil {
		return nil
	}

	s.syscallThreadMu.Lock()
	t := s.syscallThread
	s.syscallThreadMu.Unlock()
	if t == nil || t.thread == nil {
		return fmt.Errorf("HEMI gVisor subprocess has no host thread")
	}

	s.hemiGvisorPortalMu.Lock()
	defer s.hemiGvisorPortalMu.Unlock()
	if s.hemiGvisorMMID != 0 {
		return fmt.Errorf("HEMI gVisor pooled subprocess still has active MMID %d",
			s.hemiGvisorMMID)
	}
	s.hemiGvisorDevice = device
	s.hemiGvisorTGID = int32(t.thread.tgid)
	return nil
}

// InitializeAddressSpace implements platform.AddressSpaceInitializer for a new,
// empty guest address space.
func (s *subprocess) InitializeAddressSpace() error {
	s.hemiGvisorPortalMu.Lock()
	defer s.hemiGvisorPortalMu.Unlock()
	if s.hemiGvisorDevice == nil {
		return nil
	}
	return s.hemiGvisorAllocMMLocked()
}

func (s *subprocess) hemiGvisorReleaseAddressSpace() {
	s.hemiGvisorPortalMu.Lock()
	defer s.hemiGvisorPortalMu.Unlock()
	if err := s.hemiGvisorFreeMMLocked(); err != nil {
		log.Warningf("HEMI gVisor failed to free AddressSpace: %v", err)
		// Keep the target identity and MMID so that a pooled subprocess
		// cannot be mistaken for an empty AddressSpace. A subsequent acquire
		// will reject it and Release will retry the idempotent FREE_MM.
		return
	}
	s.hemiGvisorTGID = 0
	s.hemiGvisorDevice = nil
}

// hemiGvisorDestroyAddressSpace is idempotent with the normal Release path and
// covers a subprocess that died before it could be returned to the pool.
func (s *subprocess) hemiGvisorDestroyAddressSpace() {
	s.hemiGvisorReleaseAddressSpace()
}

// hemiGvisorAllocMMLocked creates an empty Host-managed address-space state.
//
// Preconditions: s.hemiGvisorPortalMu is locked.
func (s *subprocess) hemiGvisorAllocMMLocked() error {
	device := s.hemiGvisorDevice
	if device == nil {
		return nil
	}
	if s.hemiGvisorTGID <= 0 || s.hemiGvisorMMID != 0 {
		return fmt.Errorf("HEMI gVisor alloc has invalid target/MMID %d/%d",
			s.hemiGvisorTGID, s.hemiGvisorMMID)
	}
	mmid, err := device.allocateMMID()
	if err != nil {
		return err
	}

	req := linux.HemiUserspaceAllocMM{
		MMID:           mmid,
		TargetTGID:     s.hemiGvisorTGID,
		TargetDeviceFD: device.fd,
	}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(device.fd), uintptr(linux.HEMI_USERSPACE_ALLOC_MM),
		uintptr(unsafe.Pointer(&req)), 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("HEMI gVisor alloc mm ioctl for tgid %d: %w",
			s.hemiGvisorTGID, errno)
	}
	s.hemiGvisorMMID = mmid
	return nil
}

// hemiGvisorFreeMMLocked revokes portals and releases all Host state for the
// current AddressSpace. Its caller has already quiesced use of this AddressSpace;
// the Host adaptor relies on that invariant and FREE_MM is idempotent.
//
// Preconditions: s.hemiGvisorPortalMu is locked.
func (s *subprocess) hemiGvisorFreeMMLocked() error {
	device := s.hemiGvisorDevice
	mmid := s.hemiGvisorMMID
	if mmid == 0 {
		return nil
	}
	if device == nil {
		return fmt.Errorf("HEMI gVisor MMID %d has no control device", mmid)
	}
	req := linux.HemiUserspaceFreeMM{MMID: mmid}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(device.fd), uintptr(linux.HEMI_USERSPACE_FREE_MM),
		uintptr(unsafe.Pointer(&req)), 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("HEMI gVisor free mm ioctl for MMID %d: %w", mmid, errno)
	}
	s.hemiGvisorMMID = 0
	return device.drainReleases(context.Background())
}

// ForkAddressSpaceFrom implements platform.AddressSpaceForker. The destination
// subprocess is still unbound, so FORK_MM creates its first HEMI state directly.
func (s *subprocess) ForkAddressSpaceFrom(source platform.AddressSpace) error {
	parent, ok := source.(*subprocess)
	if !ok {
		return fmt.Errorf("HEMI gVisor fork source has type %T", source)
	}
	unlock := hemiGvisorLockForkPortals(parent, s)
	defer unlock()

	if parent.hemiGvisorDevice == nil && s.hemiGvisorDevice == nil {
		return nil
	}
	if parent.hemiGvisorDevice == nil || parent.hemiGvisorDevice != s.hemiGvisorDevice {
		return fmt.Errorf("HEMI gVisor fork uses different parent and child devices")
	}
	if !parent.hemiGvisorActive() || s.hemiGvisorTGID <= 0 || s.hemiGvisorMMID != 0 {
		return fmt.Errorf("HEMI gVisor fork has invalid parent/child state %d/%d/%d",
			parent.hemiGvisorMMID, s.hemiGvisorTGID, s.hemiGvisorMMID)
	}
	childMMID, err := s.hemiGvisorDevice.allocateMMID()
	if err != nil {
		return err
	}

	req := linux.HemiUserspaceForkMM{
		ParentMMID:     parent.hemiGvisorMMID,
		ChildMMID:      childMMID,
		TargetTGID:     s.hemiGvisorTGID,
		TargetDeviceFD: s.hemiGvisorDevice.fd,
	}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(s.hemiGvisorDevice.fd), uintptr(linux.HEMI_USERSPACE_FORK_MM),
		uintptr(unsafe.Pointer(&req)), 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("HEMI gVisor fork mm ioctl for parent MMID %d and child tgid %d: %w",
			parent.hemiGvisorMMID, s.hemiGvisorTGID, errno)
	}
	s.hemiGvisorMMID = childMMID
	return nil
}

func hemiGvisorLockForkPortals(parent, child *subprocess) func() {
	if parent == child {
		parent.hemiGvisorPortalMu.Lock()
		return parent.hemiGvisorPortalMu.Unlock
	}
	first, second := parent, child
	if first.hemiGvisorMMID > second.hemiGvisorMMID ||
		(first.hemiGvisorMMID == second.hemiGvisorMMID &&
			uintptr(unsafe.Pointer(first)) > uintptr(unsafe.Pointer(second))) {
		first, second = second, first
	}
	first.hemiGvisorPortalMu.Lock()
	second.hemiGvisorPortalMu.Lock()
	return func() {
		second.hemiGvisorPortalMu.Unlock()
		first.hemiGvisorPortalMu.Unlock()
	}
}

// hemiGvisorKeepSyscallUnpatched reports whether sysno must continue entering
// the host kernel so that the HEMI direct hook can observe it. All other
// syscalls retain usertrap patching. usertrap only patches call sites with an
// immediate syscall number, so a patched non-memory call site can't later issue
// one of the memory syscalls below.
func (s *subprocess) hemiGvisorKeepSyscallUnpatched(sysno uintptr) bool {
	if !s.hemiGvisorActive() {
		return false
	}
	switch sysno {
	case unix.SYS_MMAP, unix.SYS_MUNMAP, unix.SYS_MPROTECT, unix.SYS_BRK:
		return true
	default:
		return false
	}
}

func (s *subprocess) hemiGvisorActive() bool {
	return s.hemiGvisorTGID > 0 && s.hemiGvisorMMID != 0
}

func hemiGvisorContainsUserMem(addr hostarch.Addr, length uint64) bool {
	if length == 0 {
		return true
	}
	start := uint64(addr)
	end := start + length
	return start >= linux.HEMI_USERSPACE_VMAR_START &&
		end >= start && end <= linux.HEMI_USERSPACE_VMAR_END
}

func (s *subprocess) hemiGvisorUserMem(addr hostarch.Addr, data []byte, write bool) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if !hemiGvisorContainsUserMem(addr, uint64(len(data))) {
		return 0, platform.AddressSpaceIOUnavailable{}
	}
	device := s.hemiGvisorDevice
	if device == nil || !s.hemiGvisorActive() {
		return 0, platform.AddressSpaceIOUnavailable{}
	}

	req := linux.HemiUserspaceAccess{
		MMID:    s.hemiGvisorMMID,
		Addr:    uint64(addr),
		UserBuf: uint64(uintptr(unsafe.Pointer(&data[0]))),
		Len:     uint64(len(data)),
		Access:  linux.HEMI_USERSPACE_ACCESS_READ,
	}
	if write {
		req.Access = linux.HEMI_USERSPACE_ACCESS_WRITE
	}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(device.fd), uintptr(linux.HEMI_USERSPACE_ACCESS),
		uintptr(unsafe.Pointer(&req)), 0, 0, 0)
	runtime.KeepAlive(data)
	if errno != 0 {
		if errno == unix.EFAULT {
			return 0, platform.SegmentationFault{Addr: addr}
		}
		return 0, fmt.Errorf("HEMI gVisor user memory ioctl: %w", errno)
	}
	return hemiGvisorUserMemResult(addr, len(data), req.Done, req.Result)
}

func hemiGvisorUserMemResult(addr hostarch.Addr, length int, doneBytes uint64, result int32) (int, error) {
	if doneBytes > uint64(length) {
		return 0, fmt.Errorf("HEMI gVisor user memory ioctl returned invalid progress %d/%d", doneBytes, length)
	}
	done := int(doneBytes)
	if result == 0 {
		if done != length {
			return done, fmt.Errorf("HEMI gVisor user memory ioctl completed only %d/%d bytes", done, length)
		}
		return done, nil
	}
	resultErrno := unix.Errno(-result)
	if resultErrno == unix.EFAULT {
		return done, platform.SegmentationFault{Addr: addr + hostarch.Addr(done)}
	}
	if resultErrno == unix.EAGAIN {
		return done, platform.AddressSpaceFileFault{Addr: addr + hostarch.Addr(done)}
	}
	return done, fmt.Errorf("HEMI gVisor user memory access: %w", resultErrno)
}

// AddressSpaceIOAllSizes reports that HEMI owns the authoritative user page
// tables, so Sentry internal mappings must not be selected based on size.
func (s *subprocess) AddressSpaceIOAllSizes() bool {
	return s.hemiGvisorActive()
}

// AddressSpaceIOApplicablePrefix partitions ar at HEMI's authoritative
// user-memory boundaries. This lets MemoryManager use internal mappings for
// ordinary Sentry VMAs without sending a mixed range through the HEMI portal.
func (s *subprocess) AddressSpaceIOApplicablePrefix(ar hostarch.AddrRange) (hostarch.Addr, bool) {
	if !s.hemiGvisorActive() {
		return ar.Length(), false
	}
	start := hostarch.Addr(linux.HEMI_USERSPACE_VMAR_START)
	end := hostarch.Addr(linux.HEMI_USERSPACE_VMAR_END)
	if ar.Start < start {
		return min(ar.End, start) - ar.Start, false
	}
	if ar.Start < end {
		return min(ar.End, end) - ar.Start, true
	}
	return ar.Length(), false
}

// AddressSpaceIOReadIgnoresPermissions reports that HEMI CopyIn reads through
// HEMI's authoritative page tables and can service instruction-emulation reads.
func (s *subprocess) AddressSpaceIOReadIgnoresPermissions() bool {
	return s.hemiGvisorActive()
}

// AddressSpaceIOBatchSize returns one full ring batch only when this address
// space has a usable ring. Legacy AddressSpaceIO retains MemoryManager's
// smaller default buffer.
func (s *subprocess) AddressSpaceIOBatchSize() int {
	s.hemiGvisorPortalMu.Lock()
	defer s.hemiGvisorPortalMu.Unlock()
	if s.hemiGvisorActive() && s.hemiGvisorDevice != nil && s.hemiGvisorDevice.lanes != nil {
		return hemiGvisorRingBatchBytes
	}
	return 0
}

func hemiGvisorContainsUserMemSeq(ars hostarch.AddrRangeSeq) bool {
	for !ars.IsEmpty() {
		ar := ars.Head()
		if !hemiGvisorContainsUserMem(ar.Start, uint64(ar.Length())) {
			return false
		}
		ars = ars.Tail()
	}
	return true
}

// hemiGvisorAcquireRingLane acquires a reusable shared bounce buffer without
// invoking the stream. AddressSpaceIOUnavailable is therefore safe for
// MemoryManager to handle by retrying through its generic buffered path.
func (s *subprocess) hemiGvisorAcquireRingLane(ars hostarch.AddrRangeSeq) (*hemiGvisorDeviceState, *hemiGvisorRingLane, uint64, error) {
	if !hemiGvisorContainsUserMemSeq(ars) {
		return nil, nil, 0, platform.AddressSpaceIOUnavailable{}
	}

	s.hemiGvisorPortalMu.Lock()
	defer s.hemiGvisorPortalMu.Unlock()
	device := s.hemiGvisorDevice
	if device == nil || device.lanes == nil || !s.hemiGvisorActive() {
		return nil, nil, 0, platform.AddressSpaceIOUnavailable{}
	}
	select {
	case lane := <-device.lanes:
		return device, lane, s.hemiGvisorMMID, nil
	default:
		return nil, nil, 0, platform.AddressSpaceIOUnavailable{}
	}
}

func (s *subprocess) hemiGvisorTransferRingInPlace(device *hemiGvisorDeviceState, lane *hemiGvisorRingLane, mmid uint64, addr hostarch.Addr, data []byte, op uint16, enterFn hemiGvisorRingEnterFunc) (int, error) {
	s.hemiGvisorPortalMu.Lock()
	defer s.hemiGvisorPortalMu.Unlock()
	if !s.hemiGvisorActive() || s.hemiGvisorDevice != device || s.hemiGvisorMMID != mmid {
		return 0, &platform.AddressSpaceIOStreamError{Err: fmt.Errorf("HEMI gVisor address space changed during ring transfer")}
	}
	n, err := lane.transferInPlace(device.fd, mmid, addr, data, op, enterFn)
	if err != nil {
		return n, &platform.AddressSpaceIOStreamError{Err: err}
	}
	return n, nil
}

func hemiGvisorFileFaultAddr(err error) (hostarch.Addr, bool) {
	if streamErr, ok := err.(*platform.AddressSpaceIOStreamError); ok {
		err = streamErr.Err
	}
	fault, ok := err.(platform.AddressSpaceFileFault)
	return fault.Addr, ok
}

// CopyOutFromIter implements platform.AddressSpaceIOIter.CopyOutFromIter. The
// Reader fills the ring lane directly; ENTER_RING then copies from that same
// shared buffer into HEMI-managed application memory.
func (s *subprocess) CopyOutFromIter(ars hostarch.AddrRangeSeq, src safemem.Reader, handleFault platform.AddressSpaceIOFaultHandler) (int64, error) {
	return s.copyOutFromIter(ars, src, handleFault, hemiGvisorRawRingEnter)
}

func (s *subprocess) copyOutFromIter(ars hostarch.AddrRangeSeq, src safemem.Reader, handleFault platform.AddressSpaceIOFaultHandler, enterFn hemiGvisorRingEnterFunc) (int64, error) {
	device, lane, mmid, err := s.hemiGvisorAcquireRingLane(ars)
	if err != nil {
		return 0, err
	}
	defer func() { device.lanes <- lane }()

	buf := lane.mapping[hemiGvisorRingDataOffset : hemiGvisorRingDataOffset+hemiGvisorRingBatchBytes]
	var done int64
	for !ars.IsEmpty() {
		ar := ars.Head()
		if ar.Length() == 0 {
			ars = ars.Tail()
			continue
		}
		want := min(int(ar.Length()), len(buf))
		n64, srcErr := src.ReadToBlocks(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf[:want])))
		if n64 > uint64(want) {
			return done, fmt.Errorf("reader returned %d bytes for a %d-byte ring buffer", n64, want)
		}
		n := int(n64)
		if n != 0 {
			var copied int
			for copied < n {
				progress, targetErr := s.hemiGvisorTransferRingInPlace(
					device, lane, mmid, ar.Start+hostarch.Addr(copied), buf[copied:n],
					linux.HEMI_USERSPACE_RING_OP_WRITE, enterFn)
				copied += progress
				done += int64(progress)
				ars = ars.DropFirst(progress)
				if targetErr == nil {
					continue
				}
				if faultAddr, ok := hemiGvisorFileFaultAddr(targetErr); ok && handleFault != nil {
					if err := handleFault(faultAddr, hostarch.Write); err != nil {
						return done, err
					}
					continue
				}
				return done, targetErr
			}
		}
		if srcErr != nil {
			return done, srcErr
		}
		if n != want {
			return done, nil
		}
	}
	return done, nil
}

// CopyInToIter implements platform.AddressSpaceIOIter.CopyInToIter. The ring
// lane receives HEMI-managed application memory and is passed directly to the
// Writer without an intermediate MemoryManager buffer.
func (s *subprocess) CopyInToIter(ars hostarch.AddrRangeSeq, dst safemem.Writer, handleFault platform.AddressSpaceIOFaultHandler) (int64, error) {
	return s.copyInToIter(ars, dst, handleFault, hemiGvisorRawRingEnter)
}

func (s *subprocess) copyInToIter(ars hostarch.AddrRangeSeq, dst safemem.Writer, handleFault platform.AddressSpaceIOFaultHandler, enterFn hemiGvisorRingEnterFunc) (int64, error) {
	device, lane, mmid, err := s.hemiGvisorAcquireRingLane(ars)
	if err != nil {
		return 0, err
	}
	defer func() { device.lanes <- lane }()

	buf := lane.mapping[hemiGvisorRingDataOffset : hemiGvisorRingDataOffset+hemiGvisorRingBatchBytes]
	var done int64
	for !ars.IsEmpty() {
		ar := ars.Head()
		if ar.Length() == 0 {
			ars = ars.Tail()
			continue
		}
		want := min(int(ar.Length()), len(buf))
		copied, targetErr := s.hemiGvisorTransferRingInPlace(
			device, lane, mmid, ar.Start, buf[:want], linux.HEMI_USERSPACE_RING_OP_READ, enterFn)
		if copied == 0 {
			if faultAddr, ok := hemiGvisorFileFaultAddr(targetErr); ok && handleFault != nil {
				if err := handleFault(faultAddr, hostarch.Read); err != nil {
					return done, err
				}
				continue
			}
			if targetErr == nil {
				targetErr = &platform.AddressSpaceIOStreamError{Err: fmt.Errorf("HEMI gVisor ring copied 0/%d bytes without an error", want)}
			}
			return done, targetErr
		}

		written64, writeErr := dst.WriteFromBlocks(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf[:copied])))
		if written64 > uint64(copied) {
			return done, fmt.Errorf("writer consumed %d bytes from a %d-byte ring buffer", written64, copied)
		}
		written := int(written64)
		done += int64(written)
		ars = ars.DropFirst(written)
		if writeErr != nil {
			return done, writeErr
		}
		if targetErr != nil {
			if faultAddr, ok := hemiGvisorFileFaultAddr(targetErr); ok && handleFault != nil {
				if err := handleFault(faultAddr, hostarch.Read); err != nil {
					return done, err
				}
				continue
			}
			return done, targetErr
		}
		if written != copied {
			return done, nil
		}
		if copied != want {
			return done, &platform.AddressSpaceIOStreamError{Err: fmt.Errorf("HEMI gVisor ring copied only %d/%d bytes without an error", copied, want)}
		}
	}
	return done, nil
}

// EnsureAccess faults in and validates a HEMI-managed user range without
// consulting the sentry's VMA/PMA metadata.
func (s *subprocess) EnsureAccess(addr hostarch.Addr, length uint64, at hostarch.AccessType) (uint64, error) {
	if !hemiGvisorContainsUserMem(addr, length) {
		return 0, platform.AddressSpaceIOUnavailable{}
	}
	s.hemiGvisorPortalMu.Lock()
	defer s.hemiGvisorPortalMu.Unlock()
	device := s.hemiGvisorDevice
	if device == nil || !s.hemiGvisorActive() {
		return 0, platform.AddressSpaceIOUnavailable{}
	}

	var access uint32
	if at.Read {
		access |= linux.HEMI_USERSPACE_ACCESS_READ
	}
	if at.Write {
		access |= linux.HEMI_USERSPACE_ACCESS_WRITE
	}
	if access == 0 || at.Execute {
		return 0, platform.AddressSpaceIOUnavailable{}
	}

	req := linux.HemiUserspaceProbeUser{
		MMID:   s.hemiGvisorMMID,
		Addr:   uint64(addr),
		Len:    length,
		Access: access,
	}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(device.fd), uintptr(linux.HEMI_USERSPACE_PROBE_USER),
		uintptr(unsafe.Pointer(&req)), 0, 0, 0)
	if errno != 0 {
		return req.Done, fmt.Errorf("HEMI gVisor probe user ioctl: %w", errno)
	}
	if req.Result != 0 {
		if unix.Errno(-req.Result) == unix.EAGAIN {
			return req.Done, platform.AddressSpaceFileFault{Addr: addr + hostarch.Addr(req.Done)}
		}
		return req.Done, platform.SegmentationFault{Addr: addr + hostarch.Addr(req.Done)}
	}
	return req.Done, nil
}

// ReservedAddressRange returns the user virtual-address range owned by HEMI.
func (s *subprocess) ReservedAddressRange() hostarch.AddrRange {
	if !s.hemiGvisorActive() {
		return hostarch.AddrRange{}
	}
	return hostarch.AddrRange{
		Start: hostarch.Addr(linux.HEMI_USERSPACE_VMAR_START),
		End:   hostarch.Addr(linux.HEMI_USERSPACE_VMAR_END),
	}
}

func (s *subprocess) CopyIn(addr hostarch.Addr, dst []byte) (int, error) {
	if !hemiGvisorContainsUserMem(addr, uint64(len(dst))) {
		return 0, platform.AddressSpaceIOUnavailable{}
	}
	if len(dst) == 0 {
		return 0, nil
	}
	s.hemiGvisorPortalMu.Lock()
	defer s.hemiGvisorPortalMu.Unlock()
	return s.hemiGvisorCopyInLocked(addr, dst)
}

// hemiGvisorCopyInLocked copies target memory into dst.
//
// Preconditions: s.hemiGvisorPortalMu is locked.
func (s *subprocess) hemiGvisorCopyInLocked(addr hostarch.Addr, dst []byte) (int, error) {
	var done int
	if device := s.hemiGvisorDevice; device != nil && s.hemiGvisorActive() {
		if n, err, ok := device.tryRingTransfer(
			s.hemiGvisorMMID, addr, dst, linux.HEMI_USERSPACE_RING_OP_READ); ok {
			done = n
			var enterErr *hemiGvisorRingEnterError
			if err == nil || !errors.As(err, &enterErr) {
				return n, err
			}
		}
	}
	for done < len(dst) {
		end := min(done+hemiGvisorUserMemMax, len(dst))
		n, err := s.hemiGvisorUserMem(addr+hostarch.Addr(done), dst[done:end], false)
		done += n
		if err != nil {
			return done, err
		}
	}
	return done, nil
}

func (s *subprocess) CopyOut(addr hostarch.Addr, src []byte) (int, error) {
	if !hemiGvisorContainsUserMem(addr, uint64(len(src))) {
		return 0, platform.AddressSpaceIOUnavailable{}
	}
	if len(src) == 0 {
		return 0, nil
	}
	s.hemiGvisorPortalMu.Lock()
	defer s.hemiGvisorPortalMu.Unlock()
	return s.hemiGvisorCopyOutLocked(addr, src)
}

// hemiGvisorCopyOutLocked copies src into target memory.
//
// Preconditions: s.hemiGvisorPortalMu is locked.
func (s *subprocess) hemiGvisorCopyOutLocked(addr hostarch.Addr, src []byte) (int, error) {
	var done int
	if device := s.hemiGvisorDevice; device != nil && s.hemiGvisorActive() {
		if n, err, ok := device.tryRingTransfer(
			s.hemiGvisorMMID, addr, src, linux.HEMI_USERSPACE_RING_OP_WRITE); ok {
			done = n
			var enterErr *hemiGvisorRingEnterError
			if err == nil || !errors.As(err, &enterErr) {
				return n, err
			}
		}
	}
	for done < len(src) {
		end := min(done+hemiGvisorUserMemMax, len(src))
		n, err := s.hemiGvisorUserMem(addr+hostarch.Addr(done), src[done:end], true)
		done += n
		if err != nil {
			return done, err
		}
	}
	return done, nil
}

func (s *subprocess) ZeroOut(addr hostarch.Addr, toZero uintptr) (uintptr, error) {
	if !hemiGvisorContainsUserMem(addr, uint64(toZero)) {
		return 0, platform.AddressSpaceIOUnavailable{}
	}
	if toZero == 0 {
		return 0, nil
	}
	s.hemiGvisorPortalMu.Lock()
	defer s.hemiGvisorPortalMu.Unlock()
	var done uintptr
	for done < toZero {
		length := min(toZero-done, uintptr(len(hemiGvisorZeroBuffer)))
		n, err := s.hemiGvisorCopyOutLocked(addr+hostarch.Addr(done), hemiGvisorZeroBuffer[:length])
		done += uintptr(n)
		if err != nil {
			return done, err
		}
	}
	return done, nil
}

func (s *subprocess) SwapUint32(addr hostarch.Addr, value uint32) (uint32, error) {
	return s.hemiGvisorAtomicUint32(addr, linux.HEMI_USERSPACE_ATOMIC_U32_SWAP, 0, value)
}

func (s *subprocess) CompareAndSwapUint32(addr hostarch.Addr, old, value uint32) (uint32, error) {
	return s.hemiGvisorAtomicUint32(addr, linux.HEMI_USERSPACE_ATOMIC_U32_CMPXCHG, old, value)
}

func (s *subprocess) LoadUint32(addr hostarch.Addr) (uint32, error) {
	return s.hemiGvisorAtomicUint32(addr, linux.HEMI_USERSPACE_ATOMIC_U32_LOAD, 0, 0)
}

func (s *subprocess) hemiGvisorAtomicUint32(addr hostarch.Addr, op, old, new uint32) (uint32, error) {
	if !hemiGvisorContainsUserMem(addr, 4) {
		return 0, platform.AddressSpaceIOUnavailable{}
	}
	s.hemiGvisorPortalMu.Lock()
	defer s.hemiGvisorPortalMu.Unlock()
	device := s.hemiGvisorDevice
	if device == nil || !s.hemiGvisorActive() {
		return 0, platform.AddressSpaceIOUnavailable{}
	}

	req := linux.HemiUserspaceAtomicU32{
		MMID: s.hemiGvisorMMID,
		Addr: uint64(addr),
		Op:   op,
		Old:  old,
		New:  new,
	}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(device.fd), uintptr(linux.HEMI_USERSPACE_ATOMIC_U32),
		uintptr(unsafe.Pointer(&req)), 0, 0, 0)
	if errno == 0 {
		return req.Value, nil
	}
	if errno == unix.EFAULT {
		return 0, platform.SegmentationFault{Addr: addr}
	}
	if errno == unix.EAGAIN {
		return 0, platform.AddressSpaceFileFault{Addr: addr}
	}
	return 0, fmt.Errorf("HEMI gVisor atomic u32 ioctl: %w", errno)
}

func (d *hemiGvisorDeviceState) registerFileTokens(mappable memmap.Mappable, identity memmap.MappingIdentity) (uint64, uint64, error) {
	if mappable == nil || identity == nil {
		return 0, 0, fmt.Errorf("HEMI gVisor file token has no mapping provider")
	}
	d.tokenMu.Lock()
	defer d.tokenMu.Unlock()
	if d.nextToken > ^uint64(0)-2 {
		return 0, 0, fmt.Errorf("HEMI gVisor token space exhausted")
	}
	fileToken := d.nextToken + 1
	inodeToken := d.nextToken + 2
	d.nextToken = inodeToken
	if d.tokens == nil {
		d.tokens = make(map[uint64]hemiGvisorToken)
	}

	// The registry owns one identity reference for each token. These
	// references keep the provider valid after the Guest file descriptor is
	// closed and are released only after Host DRAIN_RELEASES.
	identity.IncRef()
	identity.IncRef()
	d.tokens[fileToken] = hemiGvisorToken{
		kind:     linux.HEMI_USERSPACE_RELEASE_FILE,
		mappable: mappable,
		identity: identity,
		refs:     1,
	}
	d.tokens[inodeToken] = hemiGvisorToken{
		kind:     linux.HEMI_USERSPACE_RELEASE_INODE,
		identity: identity,
		refs:     1,
	}
	return fileToken, inodeToken, nil
}

func (d *hemiGvisorDeviceState) lookupFileToken(token uint64, mappable memmap.Mappable) (memmap.Mappable, memmap.MappingIdentity, error) {
	d.tokenMu.Lock()
	defer d.tokenMu.Unlock()
	entry, ok := d.tokens[token]
	if !ok || entry.kind != linux.HEMI_USERSPACE_RELEASE_FILE ||
		entry.mappable != mappable || entry.identity == nil {
		return nil, nil, fmt.Errorf("HEMI gVisor file fault returned stale token %d", token)
	}
	entry.identity.IncRef()
	return entry.mappable, entry.identity, nil
}

// registerPageToken consumes one reference on fr. The Host returns the token
// through DRAIN_RELEASES only after it has unpinned the pageVA supplied in
// FILE_FAULT COMPLETE.
func (d *hemiGvisorDeviceState) registerPageToken(file memmap.File, fr memmap.FileRange, block safemem.Block, mapping []byte) (uint64, error) {
	d.tokenMu.Lock()
	defer d.tokenMu.Unlock()
	if d.nextToken == ^uint64(0) {
		return 0, fmt.Errorf("HEMI gVisor token space exhausted")
	}
	if d.tokens == nil {
		d.tokens = make(map[uint64]hemiGvisorToken)
	}
	d.nextToken++
	token := d.nextToken
	d.tokens[token] = hemiGvisorToken{
		kind:      linux.HEMI_USERSPACE_RELEASE_PAGE,
		file:      file,
		fileRange: fr,
		block:     block,
		mapping:   mapping,
		refs:      1,
	}
	return token, nil
}

func (d *hemiGvisorDeviceState) releaseToken(ctx context.Context, token uint64, kind uint32, count uint64) error {
	if count == 0 {
		return fmt.Errorf("HEMI gVisor release token %d has zero count", token)
	}
	d.tokenMu.Lock()
	entry, ok := d.tokens[token]
	if !ok || entry.kind != kind || count > entry.refs {
		d.tokenMu.Unlock()
		return fmt.Errorf("HEMI gVisor release token %d has invalid kind/count %d/%d", token, kind, count)
	}
	entry.refs -= count
	if entry.refs == 0 {
		delete(d.tokens, token)
	} else {
		d.tokens[token] = entry
	}
	d.tokenMu.Unlock()
	switch kind {
	case linux.HEMI_USERSPACE_RELEASE_PAGE:
		if count != 1 || entry.file == nil {
			return fmt.Errorf("HEMI gVisor page token %d has invalid ownership", token)
		}
		var unmapErr error
		if entry.mapping != nil {
			unmapErr = memutil.UnmapSlice(entry.mapping)
			if errno, ok := unmapErr.(unix.Errno); ok && errno == 0 {
				unmapErr = nil
			}
		}
		entry.file.DecRef(entry.fileRange)
		if unmapErr != nil {
			return fmt.Errorf("HEMI gVisor unmap page token %d: %w", token, unmapErr)
		}
	case linux.HEMI_USERSPACE_RELEASE_FILE, linux.HEMI_USERSPACE_RELEASE_INODE:
		if entry.identity == nil {
			return fmt.Errorf("HEMI gVisor token %d has no identity", token)
		}
		for range count {
			entry.identity.DecRef(ctx)
		}
	default:
		return fmt.Errorf("HEMI gVisor release token %d has unknown kind %d", token, kind)
	}
	return nil
}

func (d *hemiGvisorDeviceState) rollbackFileTokens(ctx context.Context, fileToken, inodeToken uint64) {
	if err := d.releaseToken(ctx, fileToken, linux.HEMI_USERSPACE_RELEASE_FILE, 1); err != nil {
		log.Warningf("HEMI gVisor failed to roll back file token: %v", err)
	}
	if err := d.releaseToken(ctx, inodeToken, linux.HEMI_USERSPACE_RELEASE_INODE, 1); err != nil {
		log.Warningf("HEMI gVisor failed to roll back inode token: %v", err)
	}
}

func (d *hemiGvisorDeviceState) drainReleases(ctx context.Context) error {
	for {
		batch := linux.HemiUserspaceReleaseBatch{}
		errno := hostsyscall.RawSyscallErrno6(
			unix.SYS_IOCTL, uintptr(d.fd), uintptr(linux.HEMI_USERSPACE_DRAIN_RELEASES),
			uintptr(unsafe.Pointer(&batch)), 0, 0, 0)
		if errno != 0 {
			return fmt.Errorf("HEMI gVisor drain releases ioctl: %w", errno)
		}
		if batch.Count > linux.HEMI_USERSPACE_RELEASE_MAX || batch.Flags != 0 {
			return fmt.Errorf("HEMI gVisor drain returned invalid header: count=%d flags=%d", batch.Count, batch.Flags)
		}
		if batch.Count == 0 {
			return nil
		}
		for i := uint32(0); i < batch.Count; i++ {
			record := batch.Records[i]
			if record.Reserved != 0 {
				return fmt.Errorf("HEMI gVisor drain returned reserved data for token %d", record.Token)
			}
			if err := d.releaseToken(ctx, record.Token, record.Type, record.Count); err != nil {
				return err
			}
		}
	}
}

func hemiGvisorPageFaultErrorCode(at hostarch.AccessType) uint64 {
	errorCode := uint64(linux.X86_PF_USER)
	if at.Write {
		errorCode |= linux.X86_PF_WRITE
	}
	if at.Execute {
		errorCode |= linux.X86_PF_INSTR
	}
	return errorCode
}

func (d *hemiGvisorDeviceState) prepareFilePage(ctx context.Context, t memmap.Translation, offset uint64) (linux.HemiUserspaceFilePage, error) {
	delta := offset - t.Source.Start
	if t.Offset > ^uint64(0)-delta {
		return linux.HemiUserspaceFilePage{}, fmt.Errorf("HEMI gVisor translated file offset overflow")
	}
	fileOffset := t.Offset + delta
	if fileOffset > ^uint64(0)-uint64(hostarch.PageSize) {
		return linux.HemiUserspaceFilePage{}, fmt.Errorf("HEMI gVisor translated file page overflow")
	}
	fr := memmap.FileRange{Start: fileOffset, End: fileOffset + uint64(hostarch.PageSize)}
	t.File.IncRef(fr, pgalloc.MemoryCgroupIDFromContext(ctx))

	mapAccess := hostarch.Read
	direct := t.Perms.Write
	if direct {
		mapAccess = hostarch.ReadWrite
	}
	blocks, mapErr := t.File.MapInternal(fr, mapAccess)
	if mapErr == nil && direct && blocks.NumBlocks() == 1 &&
		blocks.NumBytes() == uint64(hostarch.PageSize) &&
		blocks.Head().Addr()%uintptr(hostarch.PageSize) == 0 {
		block := blocks.Head()
		token, err := d.registerPageToken(t.File, fr, block, nil)
		if err != nil {
			t.File.DecRef(fr)
			return linux.HemiUserspaceFilePage{}, err
		}
		return linux.HemiUserspaceFilePage{
			PageToken: token,
			PageVA:    uint64(block.Addr()),
		}, nil
	}

	mapping, err := memutil.MapSlice(
		0, uintptr(hostarch.PageSize), unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS, ^uintptr(0), 0)
	if err != nil {
		t.File.DecRef(fr)
		return linux.HemiUserspaceFilePage{}, err
	}
	cleanup := func() {
		_ = memutil.UnmapSlice(mapping)
		t.File.DecRef(fr)
	}

	switch mapErr.(type) {
	case nil:
		n, err := safemem.CopySeq(
			safemem.BlockSeqOf(safemem.BlockFromSafeSlice(mapping)), blocks)
		if err != nil || n != uint64(hostarch.PageSize) {
			cleanup()
			if err != nil {
				return linux.HemiUserspaceFilePage{}, fmt.Errorf("HEMI gVisor copy file page: %d/%d bytes: %w", n, hostarch.PageSize, err)
			}
			return linux.HemiUserspaceFilePage{}, fmt.Errorf("HEMI gVisor copy file page: %d/%d bytes", n, hostarch.PageSize)
		}
	case memmap.BufferedIOFallbackErr:
		n, err := t.File.BufferReadAt(fileOffset, mapping)
		if n > uint64(hostarch.PageSize) || (err != nil && !errors.Is(err, io.EOF)) {
			cleanup()
			return linux.HemiUserspaceFilePage{}, fmt.Errorf("HEMI gVisor buffered file page read: %d/%d bytes: %w", n, hostarch.PageSize, err)
		}
	default:
		cleanup()
		return linux.HemiUserspaceFilePage{}, fmt.Errorf("HEMI gVisor map file page: %w", mapErr)
	}

	block := safemem.BlockFromSafeSlice(mapping)
	token, err := d.registerPageToken(t.File, fr, block, mapping)
	if err != nil {
		cleanup()
		return linux.HemiUserspaceFilePage{}, err
	}
	return linux.HemiUserspaceFilePage{
		PageToken: token,
		PageVA:    uint64(block.Addr()),
	}, nil
}

func (d *hemiGvisorDeviceState) rollbackPageTokens(ctx context.Context, pages []linux.HemiUserspaceFilePage) {
	for _, page := range pages {
		if err := d.releaseToken(ctx, page.PageToken, linux.HEMI_USERSPACE_RELEASE_PAGE, 1); err != nil {
			log.Warningf("HEMI gVisor failed to roll back page token: %v", err)
		}
	}
}

// ResolveFileFault implements platform.AddressSpaceFilePager. MemoryManager
// holds mappingMu for reading, so Translate is synchronized with invalidation
// for the VMA whose tokens were registered by PublishPrivateFileMapping.
func (s *subprocess) ResolveFileFault(ctx context.Context, addr hostarch.Addr, at hostarch.AccessType, mappable memmap.Mappable, faultMR, optionalMR memmap.MappableRange) (bool, error) {
	if !hemiGvisorContainsUserMem(addr, 1) {
		return false, nil
	}
	s.hemiGvisorPortalMu.Lock()
	defer s.hemiGvisorPortalMu.Unlock()
	device := s.hemiGvisorDevice
	if device == nil || !s.hemiGvisorActive() {
		return false, nil
	}

	req := linux.HemiUserspaceFileFault{
		MMID:           s.hemiGvisorMMID,
		Addr:           uint64(addr),
		ErrorCode:      hemiGvisorPageFaultErrorCode(at),
		Phase:          linux.HEMI_USERSPACE_FILE_FAULT_QUERY,
		TargetTGID:     s.hemiGvisorTGID,
		TargetDeviceFD: device.fd,
	}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(device.fd), uintptr(linux.HEMI_USERSPACE_FILE_FAULT),
		uintptr(unsafe.Pointer(&req)), 0, 0, 0)
	if errno != 0 {
		return false, fmt.Errorf("HEMI gVisor file fault query ioctl: %w", errno)
	}
	if req.Result != 0 {
		return false, fmt.Errorf("HEMI gVisor file fault query returned result %d", req.Result)
	}
	switch req.Action {
	case linux.HEMI_USERSPACE_FILE_FAULT_HANDLED:
		if req.NumPages != 0 {
			return false, fmt.Errorf("HEMI gVisor handled file fault returned %d pages", req.NumPages)
		}
		return true, nil
	case linux.HEMI_USERSPACE_FILE_FAULT_GUEST_HANDLE:
		if req.NumPages != 0 {
			return false, fmt.Errorf("HEMI gVisor fallback file fault returned %d pages", req.NumPages)
		}
		return false, nil
	case linux.HEMI_USERSPACE_FILE_FAULT_GET_FILE_PAGE:
	default:
		return false, fmt.Errorf("HEMI gVisor file fault query returned unknown action %d", req.Action)
	}
	if req.NumPages == 0 || req.NumPages > linux.HEMI_USERSPACE_FILE_FAULT_MAX_PAGES ||
		req.Offset != faultMR.Start {
		return false, fmt.Errorf("HEMI gVisor file fault returned invalid range token=%d offset=%#x pages=%d",
			req.FileToken, req.Offset, req.NumPages)
	}

	provider, identity, err := device.lookupFileToken(req.FileToken, mappable)
	if err != nil {
		return false, err
	}
	defer identity.DecRef(ctx)

	end := req.Offset + uint64(req.NumPages)*uint64(hostarch.PageSize)
	if end < req.Offset || end > optionalMR.End {
		end = optionalMR.End
	}
	required := memmap.MappableRange{Start: req.Offset, End: end}
	translateAccess := at
	if translateAccess.Write {
		translateAccess.Read = true
		translateAccess.Write = false
	}
	translations, translateErr := provider.Translate(ctx, required, required, translateAccess)
	if err := memmap.CheckTranslateResult(required, required, translateAccess, translations, translateErr); err != nil {
		return false, err
	}

	pages := make([]linux.HemiUserspaceFilePage, 0, req.NumPages)
	translation := 0
	for offset := req.Offset; offset < end; offset += uint64(hostarch.PageSize) {
		for translation < len(translations) && translations[translation].Source.End <= offset {
			translation++
		}
		if translation == len(translations) ||
			!translations[translation].Source.Contains(offset) ||
			translations[translation].Source.End-offset < uint64(hostarch.PageSize) {
			break
		}
		page, err := device.prepareFilePage(ctx, translations[translation], offset)
		if err != nil {
			if len(pages) == 0 {
				return false, err
			}
			break
		}
		pages = append(pages, page)
	}
	if len(pages) == 0 {
		if translateErr != nil {
			return false, translateErr
		}
		return false, fmt.Errorf("HEMI gVisor file translation did not cover fault offset %#x", req.Offset)
	}

	req.Phase = linux.HEMI_USERSPACE_FILE_FAULT_COMPLETE
	req.NumPages = uint32(len(pages))
	copy(req.Pages[:], pages)
	errno = hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(device.fd), uintptr(linux.HEMI_USERSPACE_FILE_FAULT),
		uintptr(unsafe.Pointer(&req)), 0, 0, 0)
	runtime.KeepAlive(pages)
	if errno != 0 {
		device.rollbackPageTokens(ctx, pages)
		switch errno {
		case unix.EALREADY:
			return true, nil
		case unix.EAGAIN:
			return false, nil
		default:
			return false, fmt.Errorf("HEMI gVisor file fault complete ioctl: %w", errno)
		}
	}

	// COMPLETE transfers every page token to the Host/core even when the
	// resulting action falls back. Only DRAIN_RELEASES may release them now.
	if err := device.drainReleases(ctx); err != nil {
		return false, err
	}
	if req.Result != 0 {
		return false, fmt.Errorf("HEMI gVisor file fault complete returned result %d", req.Result)
	}
	switch req.Action {
	case linux.HEMI_USERSPACE_FILE_FAULT_HANDLED:
		return true, nil
	case linux.HEMI_USERSPACE_FILE_FAULT_GUEST_HANDLE:
		return false, nil
	default:
		return false, fmt.Errorf("HEMI gVisor file fault complete returned unknown action %d", req.Action)
	}
}

// PublishPrivateFileMapping implements platform.AddressSpacePrivateFileMapper.
// The Guest VMA already exists, so Host rejection is a clean fallback. To
// prevent Host and Guest address-space divergence, only mappings whose actual
// address is inside HEMI's VMAR are offered and MAP_FIXED is used to require
// that exact address.
func (s *subprocess) PublishPrivateFileMapping(ctx context.Context, addr hostarch.Addr, length, prot, flags uint64, guestFD int32, offset uint64, mappable memmap.Mappable, identity memmap.MappingIdentity) error {
	if flags&linux.MAP_PRIVATE == 0 || flags&linux.MAP_SHARED != 0 ||
		!hemiGvisorContainsUserMem(addr, length) {
		return nil
	}

	s.hemiGvisorPortalMu.Lock()
	defer s.hemiGvisorPortalMu.Unlock()
	device := s.hemiGvisorDevice
	if device == nil || !s.hemiGvisorActive() {
		return nil
	}
	fileToken, inodeToken, err := device.registerFileTokens(mappable, identity)
	if err != nil {
		return err
	}
	req := linux.HemiUserspaceMapFile{
		MMID: s.hemiGvisorMMID,
		Args: [6]uint64{
			uint64(addr),
			length,
			prot,
			flags | linux.MAP_FIXED,
			uint64(int64(guestFD)),
			offset,
		},
		FileToken:      fileToken,
		InodeToken:     inodeToken,
		TargetTGID:     s.hemiGvisorTGID,
		TargetDeviceFD: device.fd,
	}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(device.fd), uintptr(linux.HEMI_USERSPACE_MAP_FILE),
		uintptr(unsafe.Pointer(&req)), 0, 0, 0)
	if errno != 0 {
		device.rollbackFileTokens(ctx, fileToken, inodeToken)
		return fmt.Errorf("HEMI gVisor map file ioctl: %w", errno)
	}

	// Core owns the tokens once MAP_FILE reaches it, including GuestHandle
	// and semantic-error results. DRAIN_RELEASES is the only valid release
	// path from this point.
	if err := device.drainReleases(ctx); err != nil {
		return err
	}
	if req.Reserved != 0 {
		return fmt.Errorf("HEMI gVisor map file returned reserved data")
	}
	switch req.Action {
	case linux.HEMI_USERSPACE_MAP_GUEST_HANDLE:
		if req.Result != 0 {
			return fmt.Errorf("HEMI gVisor map fallback returned result %#x", req.Result)
		}
		return nil
	case linux.HEMI_USERSPACE_MAP_HANDLED:
		if req.Result < 0 {
			return nil
		}
		if req.Result != int64(addr) {
			return fmt.Errorf("HEMI gVisor map returned address %#x, want %#x", req.Result, addr)
		}
		return nil
	default:
		return fmt.Errorf("HEMI gVisor map returned unknown action %d", req.Action)
	}
}
