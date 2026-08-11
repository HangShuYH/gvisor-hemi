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
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/hostsyscall"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

const hemiGvisorDevicePath = "/dev/hemi_userspace"

const hemiGvisorUserMemMax = 16 * hostarch.PageSize

const (
	hemiGvisorRingLaneCount        = 32
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
	_ platform.AddressSpaceInitializer               = (*subprocess)(nil)
	_ platform.AddressSpaceForker                    = (*subprocess)(nil)
	_ platform.AddressSpaceFilePager                 = (*subprocess)(nil)
	_ platform.AddressSpaceIOIter                    = (*subprocess)(nil)
	_ platform.AddressSpaceIOWriteIgnoresPermissions = (*subprocess)(nil)
	_ platform.AddressSpacePrivateFileMapper         = (*subprocess)(nil)
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
	inodes    map[platform.PrivateFileIdentity]uint64

	releaseMapping []byte
	releaseCount   uint32
	releaseStride  uint32
	releaseWake    chan struct{}
}

type hemiGvisorToken struct {
	kind     uint32
	provider platform.PrivateFileProvider
	identity platform.PrivateFileIdentity
	refs     uint64
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
	deviceFD := int32(deviceFile.FD())
	releaseMapping, releaseSetup, err := hemiGvisorSetupReleaseQueues(deviceFD)
	if err != nil {
		log.Warningf("HEMI release queue setup failed; disabling HEMI: %v", err)
		return
	}
	state := &hemiGvisorDeviceState{
		file:           deviceFile,
		fd:             deviceFD,
		tokens:         make(map[uint64]hemiGvisorToken),
		inodes:         make(map[platform.PrivateFileIdentity]uint64),
		releaseMapping: releaseMapping,
		releaseCount:   releaseSetup.QueueCount,
		releaseStride:  releaseSetup.QueueStride,
		releaseWake:    make(chan struct{}, 1),
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
	for {
		select {
		case <-ticker.C:
		case <-d.releaseWake:
		}
		if err := d.drainReleases(context.Background()); err != nil {
			log.Warningf("HEMI gVisor periodic release drain failed: %v", err)
		}
	}
}

func (d *hemiGvisorDeviceState) notifyReleaseDrain() {
	if d == nil || d.releaseWake == nil {
		return
	}
	select {
	case d.releaseWake <- struct{}{}:
	default:
	}
}

func hemiGvisorCurrentDevice() *hemiGvisorDeviceState {
	hemiGvisorDevice.Lock()
	defer hemiGvisorDevice.Unlock()
	return hemiGvisorDevice.state
}

func hemiGvisorSetupReleaseQueues(deviceFD int32) ([]byte, linux.HemiUserspaceReleaseSetup, error) {
	setup := linux.HemiUserspaceReleaseSetup{}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(deviceFD), uintptr(linux.HEMI_USERSPACE_SETUP_RELEASES),
		uintptr(unsafe.Pointer(&setup)), 0, 0, 0)
	if errno != 0 {
		return nil, setup, errno
	}
	ringSize := uint64((*linux.HemiUserspaceReleaseRing)(nil).SizeBytes())
	required := uint64(setup.QueueCount) * uint64(setup.QueueStride)
	if setup.QueueCount == 0 ||
		setup.QueueStride < uint32(ringSize) ||
		setup.QueueStride != linux.HEMI_USERSPACE_RELEASE_QUEUE_STRIDE ||
		required > setup.MmapSize ||
		setup.MmapSize == 0 ||
		setup.MmapSize%uint64(hostarch.PageSize) != 0 ||
		setup.MmapOffset%uint64(hostarch.PageSize) != 0 ||
		uint64(uintptr(setup.MmapSize)) != setup.MmapSize ||
		uint64(uintptr(setup.MmapOffset)) != setup.MmapOffset {
		return nil, setup, fmt.Errorf("invalid HEMI release queue setup: %+v", setup)
	}
	mapping, err := memutil.MapSlice(
		0, uintptr(setup.MmapSize), unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED, uintptr(uint32(deviceFD)), uintptr(setup.MmapOffset))
	if err != nil {
		return nil, setup, err
	}
	return mapping, setup, nil
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

// tryRingTransfer falls back only when the transfer is too small or ring setup
// is unavailable. An eligible transfer waits for a lane instead of spilling
// into the contended scalar portal when all lanes are temporarily busy.
func (d *hemiGvisorDeviceState) tryRingTransfer(mmid uint64, addr hostarch.Addr, data []byte, op uint16) (int, error, bool) {
	if d == nil || d.lanes == nil || !hemiGvisorUseRing(len(data)) {
		return 0, nil, false
	}
	lane := <-d.lanes
	n, err := lane.transfer(d.fd, mmid, addr, data, op, hemiGvisorRawRingEnter)
	d.lanes <- lane
	return n, err, true
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
	if s.hemiGvisorDevice == nil {
		return nil
	}
	return s.hemiGvisorAllocMM()
}

func (s *subprocess) hemiGvisorReleaseAddressSpace() {
	if err := s.hemiGvisorFreeMM(); err != nil {
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

// hemiGvisorAllocMM creates an empty Host-managed address-space state.
func (s *subprocess) hemiGvisorAllocMM() error {
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

// hemiGvisorFreeMM revokes portals and releases all Host state for the
// current AddressSpace. Its caller has already quiesced use of this AddressSpace;
// the Host adaptor relies on that invariant and FREE_MM is idempotent.
func (s *subprocess) hemiGvisorFreeMM() error {
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
	device.notifyReleaseDrain()
	return nil
}

// ForkAddressSpaceFrom implements platform.AddressSpaceForker. The destination
// subprocess is still unbound, so FORK_MM creates its first HEMI state directly.
func (s *subprocess) ForkAddressSpaceFrom(source platform.AddressSpace) error {
	parent, ok := source.(*subprocess)
	if !ok {
		return fmt.Errorf("HEMI gVisor fork source has type %T", source)
	}
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

func (s *subprocess) hemiGvisorUserMem(addr hostarch.Addr, data []byte, access uint32) (int, error) {
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
		Access:  access,
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

// hemiGvisorAcquireRingLane waits for a reusable shared bounce buffer without
// invoking the stream. AddressSpaceIOUnavailable is returned only before the
// stream is consumed, when the range or device cannot use the ring at all.
func (s *subprocess) hemiGvisorAcquireRingLane(ars hostarch.AddrRangeSeq) (*hemiGvisorDeviceState, *hemiGvisorRingLane, uint64, error) {
	if !hemiGvisorContainsUserMemSeq(ars) {
		return nil, nil, 0, platform.AddressSpaceIOUnavailable{}
	}

	device := s.hemiGvisorDevice
	if device == nil || device.lanes == nil || !s.hemiGvisorActive() {
		return nil, nil, 0, platform.AddressSpaceIOUnavailable{}
	}
	lane := <-device.lanes
	return device, lane, s.hemiGvisorMMID, nil
}

func (s *subprocess) hemiGvisorTransferRingInPlace(device *hemiGvisorDeviceState, lane *hemiGvisorRingLane, mmid uint64, addr hostarch.Addr, data []byte, op uint16, enterFn hemiGvisorRingEnterFunc) (int, error) {
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
	return s.hemiGvisorCopyIn(addr, dst)
}

// hemiGvisorCopyIn copies target memory into dst.
func (s *subprocess) hemiGvisorCopyIn(addr hostarch.Addr, dst []byte) (int, error) {
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
		n, err := s.hemiGvisorUserMem(
			addr+hostarch.Addr(done), dst[done:end], linux.HEMI_USERSPACE_ACCESS_READ)
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
	return s.hemiGvisorCopyOut(addr, src)
}

// hemiGvisorCopyOut copies src into target memory.
func (s *subprocess) hemiGvisorCopyOut(addr hostarch.Addr, src []byte) (int, error) {
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
		n, err := s.hemiGvisorUserMem(
			addr+hostarch.Addr(done), src[done:end], linux.HEMI_USERSPACE_ACCESS_WRITE)
		done += n
		if err != nil {
			return done, err
		}
	}
	return done, nil
}

// CopyOutIgnoringPermissions performs a privileged Sentry write through the
// scalar portal. The Host preserves the Guest PTE permissions and establishes
// private COW ownership before modifying an otherwise read-only frame.
func (s *subprocess) CopyOutIgnoringPermissions(addr hostarch.Addr, src []byte) (int, error) {
	if !hemiGvisorContainsUserMem(addr, uint64(len(src))) {
		return 0, platform.AddressSpaceIOUnavailable{}
	}
	if len(src) == 0 {
		return 0, nil
	}

	var done int
	for done < len(src) {
		end := min(done+hemiGvisorUserMemMax, len(src))
		n, err := s.hemiGvisorUserMem(
			addr+hostarch.Addr(done), src[done:end],
			linux.HEMI_USERSPACE_ACCESS_WRITE|linux.HEMI_USERSPACE_ACCESS_IGNORE_PERMISSIONS)
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
	var done uintptr
	for done < toZero {
		length := min(toZero-done, uintptr(len(hemiGvisorZeroBuffer)))
		n, err := s.hemiGvisorCopyOut(addr+hostarch.Addr(done), hemiGvisorZeroBuffer[:length])
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

func (d *hemiGvisorDeviceState) registerFileTokens(provider platform.PrivateFileProvider) (uint64, uint64, error) {
	if provider == nil {
		return 0, 0, fmt.Errorf("HEMI gVisor file token has no mapping provider")
	}
	identity := provider.InodeIdentity()
	d.tokenMu.Lock()
	defer d.tokenMu.Unlock()
	inodeToken, inodeExists := d.inodes[identity]
	tokenCount := uint64(1)
	if !inodeExists {
		tokenCount++
	}
	if d.nextToken > ^uint64(0)-tokenCount {
		return 0, 0, fmt.Errorf("HEMI gVisor token space exhausted")
	}
	fileToken := d.nextToken + 1
	d.nextToken = fileToken
	if d.tokens == nil {
		d.tokens = make(map[uint64]hemiGvisorToken)
	}
	if d.inodes == nil {
		d.inodes = make(map[platform.PrivateFileIdentity]uint64)
	}

	// Each file token owns its mapping provider. A stable inode token is shared
	// by mappings of the same file identity and owns one additional provider
	// reference until the core releases its final inode reference.
	provider.IncRef()
	d.tokens[fileToken] = hemiGvisorToken{
		kind:     linux.HEMI_USERSPACE_RELEASE_FILE,
		provider: provider,
		refs:     1,
	}
	if inodeExists {
		entry := d.tokens[inodeToken]
		entry.refs++
		d.tokens[inodeToken] = entry
	} else {
		d.nextToken++
		inodeToken = d.nextToken
		provider.IncRef()
		d.tokens[inodeToken] = hemiGvisorToken{
			kind:     linux.HEMI_USERSPACE_RELEASE_INODE,
			provider: provider,
			identity: identity,
			refs:     1,
		}
		d.inodes[identity] = inodeToken
	}
	return fileToken, inodeToken, nil
}

func (d *hemiGvisorDeviceState) lookupFileToken(token uint64) (platform.PrivateFileProvider, error) {
	d.tokenMu.Lock()
	defer d.tokenMu.Unlock()
	entry, ok := d.tokens[token]
	if !ok || entry.kind != linux.HEMI_USERSPACE_RELEASE_FILE ||
		entry.provider == nil {
		return nil, fmt.Errorf("HEMI gVisor file fault returned stale token %d", token)
	}
	entry.provider.IncRef()
	return entry.provider, nil
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
	last := entry.refs == 0
	if entry.refs == 0 {
		delete(d.tokens, token)
		if kind == linux.HEMI_USERSPACE_RELEASE_INODE {
			delete(d.inodes, entry.identity)
		}
	} else {
		d.tokens[token] = entry
	}
	d.tokenMu.Unlock()
	switch kind {
	case linux.HEMI_USERSPACE_RELEASE_FILE:
		if entry.provider == nil {
			return fmt.Errorf("HEMI gVisor token %d has no provider", token)
		}
		if last {
			entry.provider.RemoveMapping(ctx)
		}
		for range count {
			entry.provider.DecRef(ctx)
		}
	case linux.HEMI_USERSPACE_RELEASE_INODE:
		if entry.provider == nil {
			return fmt.Errorf("HEMI gVisor inode token %d has no provider", token)
		}
		if last {
			entry.provider.DecRef(ctx)
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
	for queue := uint32(0); queue < d.releaseCount; queue++ {
		offset := uint64(queue) * uint64(d.releaseStride)
		ring := (*linux.HemiUserspaceReleaseRing)(
			unsafe.Pointer(&d.releaseMapping[offset]))
		head := atomic.LoadUint32(&ring.Head)
		tail := atomic.LoadUint32(&ring.Tail)
		if head >= linux.HEMI_USERSPACE_RELEASE_RING_ENTRIES ||
			tail >= linux.HEMI_USERSPACE_RELEASE_RING_ENTRIES {
			return fmt.Errorf("HEMI gVisor release queue %d has invalid indices %d/%d", queue, head, tail)
		}
		for head != tail {
			record := ring.Records[head]
			if record.Reserved != 0 || record.Token == 0 || record.Count == 0 {
				return fmt.Errorf("HEMI gVisor release queue %d returned invalid record %+v", queue, record)
			}
			if err := d.releaseToken(ctx, record.Token, record.Type, record.Count); err != nil {
				return err
			}
			head = (head + 1) % linux.HEMI_USERSPACE_RELEASE_RING_ENTRIES
			atomic.StoreUint32(&ring.Head, head)
		}
	}
	return nil
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

type hemiGvisorFileRangeRef struct {
	file memmap.File
	fr   memmap.FileRange
}

func hemiGvisorReleaseFileRanges(refs []hemiGvisorFileRangeRef) {
	for _, ref := range refs {
		ref.file.DecRef(ref.fr)
	}
}

func hemiGvisorTranslateFilePages(ctx context.Context, provider platform.PrivateFileProvider, offset uint64, count uint32, at hostarch.AccessType) ([]linux.HemiUserspaceFilePage, []hemiGvisorFileRangeRef, error) {
	end := offset + uint64(count)*uint64(hostarch.PageSize)
	if end < offset {
		return nil, nil, fmt.Errorf("HEMI gVisor file fault range overflows at offset %#x", offset)
	}

	// Private mappings always source data through a readable translation;
	// HEMI performs the write-fault COW after importing the page-cache page.
	perms := at
	perms.Read = true
	perms.Write = false
	required := memmap.MappableRange{Start: offset, End: end}
	optional := required
	ts, translateErr := provider.Translate(ctx, required, optional, perms)

	pages := make([]linux.HemiUserspaceFilePage, 0, count)
	refs := make([]hemiGvisorFileRangeRef, 0, len(ts))
	for _, t := range ts {
		refs = append(refs, hemiGvisorFileRangeRef{
			file: t.File,
			fr:   t.FileRange(),
		})
	}
	next := offset
	for _, t := range ts {
		if t.Source.End <= next {
			continue
		}
		if t.Source.Start > next {
			break
		}
		sourceEnd := min(t.Source.End, end)
		hostOffset := t.Offset + next - t.Source.Start
		fr := memmap.FileRange{
			Start: hostOffset,
			End:   hostOffset + sourceEnd - next,
		}
		fd, err := t.File.DataFD(fr)
		if err != nil {
			hemiGvisorReleaseFileRanges(refs)
			return nil, nil, err
		}
		if fd < 0 || hostOffset%uint64(hostarch.PageSize) != 0 {
			hemiGvisorReleaseFileRanges(refs)
			return nil, nil, fmt.Errorf("HEMI gVisor translation returned fd=%d offset=%#x", fd, hostOffset)
		}
		for next < sourceEnd {
			pages = append(pages, linux.HemiUserspaceFilePage{
				HostFD:     int64(fd),
				HostOffset: hostOffset,
			})
			next += uint64(hostarch.PageSize)
			hostOffset += uint64(hostarch.PageSize)
		}
		if next == end {
			break
		}
	}
	if len(pages) == 0 {
		hemiGvisorReleaseFileRanges(refs)
		if translateErr != nil {
			return nil, nil, translateErr
		}
		return nil, nil, fmt.Errorf("HEMI gVisor translation did not cover file offset %#x", offset)
	}
	return pages, refs, nil
}

// ResolveFileFault implements platform.AddressSpaceFilePager. HEMI owns the
// mapping; gVisor only resolves the opaque file token returned by the core.
func (s *subprocess) ResolveFileFault(ctx context.Context, addr hostarch.Addr, at hostarch.AccessType, ignorePermissions bool) (bool, error) {
	if !hemiGvisorContainsUserMem(addr, 1) {
		return false, nil
	}
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
	if ignorePermissions {
		req.ErrorCode |= linux.HEMI_USERSPACE_PF_IGNORE_PERMISSIONS
	}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(device.fd), uintptr(linux.HEMI_USERSPACE_FILE_FAULT),
		uintptr(unsafe.Pointer(&req)), 0, 0, 0)
	if errno != 0 {
		return false, fmt.Errorf("HEMI gVisor file fault query ioctl: %w", errno)
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
	if req.NumPages == 0 ||
		req.NumPages > linux.HEMI_USERSPACE_FILE_FAULT_MAX_PAGES ||
		req.Offset%uint64(hostarch.PageSize) != 0 {
		return false, fmt.Errorf("HEMI gVisor file fault returned invalid range token=%d offset=%#x pages=%d",
			req.FileToken, req.Offset, req.NumPages)
	}

	provider, err := device.lookupFileToken(req.FileToken)
	if err != nil {
		return false, err
	}
	defer provider.DecRef(ctx)

	pages, refs, err := hemiGvisorTranslateFilePages(
		ctx, provider, req.Offset, req.NumPages, at)
	if err != nil {
		return false, err
	}
	defer hemiGvisorReleaseFileRanges(refs)

	req.Phase = linux.HEMI_USERSPACE_FILE_FAULT_COMPLETE
	req.PageSource = linux.HEMI_USERSPACE_FILE_PAGES_HOST_FD
	req.NumPages = uint32(len(pages))
	copy(req.Pages[:], pages)
	errno = hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(device.fd), uintptr(linux.HEMI_USERSPACE_FILE_FAULT),
		uintptr(unsafe.Pointer(&req)), 0, 0, 0)
	runtime.KeepAlive(pages)
	if errno != 0 {
		switch errno {
		case unix.EALREADY:
			return true, nil
		case unix.EAGAIN:
			return false, nil
		default:
			return false, fmt.Errorf("HEMI gVisor file fault complete ioctl: %w", errno)
		}
	}

	// COMPLETE synchronously acquires Host page-cache references. gVisor may
	// drop its temporary memmap.File references when the ioctl returns.
	switch req.Action {
	case linux.HEMI_USERSPACE_FILE_FAULT_HANDLED:
		return true, nil
	case linux.HEMI_USERSPACE_FILE_FAULT_GUEST_HANDLE:
		return false, nil
	default:
		return false, fmt.Errorf("HEMI gVisor file fault complete returned unknown action %d", req.Action)
	}
}

// MapPrivateFile implements platform.AddressSpacePrivateFileMapper. gVisor
// validates the Guest file and returns provider tokens; HEMI remains the only
// owner of the resulting VMA.
func (s *subprocess) MapPrivateFile(ctx context.Context, addr hostarch.Addr, length, prot, flags uint64, guestFD int32, offset uint64, provider platform.PrivateFileProvider) (hostarch.Addr, bool, error) {
	if flags&linux.MAP_PRIVATE == 0 || flags&linux.MAP_SHARED != 0 {
		return 0, false, nil
	}

	device := s.hemiGvisorDevice
	if device == nil || !s.hemiGvisorActive() {
		return 0, false, nil
	}
	if err := provider.AddMapping(ctx, length, offset); err != nil {
		return 0, true, err
	}
	fileToken, inodeToken, err := device.registerFileTokens(provider)
	if err != nil {
		provider.RemoveMapping(ctx)
		return 0, true, err
	}
	req := linux.HemiUserspaceMapFile{
		MMID: s.hemiGvisorMMID,
		Args: [6]uint64{
			uint64(addr),
			length,
			prot,
			flags,
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
		return 0, true, fmt.Errorf("HEMI gVisor map file ioctl: %w", errno)
	}

	// Core owns the tokens once MAP_FILE reaches it, including GuestHandle
	// and semantic-error results. The release goroutine owns them from here.
	device.notifyReleaseDrain()
	if req.Reserved != 0 {
		return 0, true, fmt.Errorf("HEMI gVisor map file returned reserved data")
	}
	switch req.Action {
	case linux.HEMI_USERSPACE_MAP_GUEST_HANDLE:
		if req.Result != 0 {
			return 0, true, fmt.Errorf("HEMI gVisor map fallback returned result %#x", req.Result)
		}
		return 0, false, nil
	case linux.HEMI_USERSPACE_MAP_HANDLED:
		if req.Result < 0 {
			return 0, true, linuxerr.ErrorFromUnix(unix.Errno(-req.Result))
		}
		return hostarch.Addr(req.Result), true, nil
	default:
		return 0, true, fmt.Errorf("HEMI gVisor map returned unknown action %d", req.Action)
	}
}
