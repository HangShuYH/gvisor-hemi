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
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/hostsyscall"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

const hemiGvisorDevicePath = "/dev/hemi_gvisor"

const hemiGvisorUserMemMax = 16 * hostarch.PageSize

const (
	hemiGvisorRingLaneCount        = 4
	hemiGvisorRingEntries          = 8
	hemiGvisorRingHeaderSize       = 64
	hemiGvisorRingDescriptorOffset = hemiGvisorRingHeaderSize
	hemiGvisorRingDescriptorSize   = 64
	hemiGvisorRingDataOffset       = hostarch.PageSize
	hemiGvisorRingDataStride       = 16 * hostarch.PageSize
	hemiGvisorRingSlotBytes        = hemiGvisorRingDataStride
	hemiGvisorRingMapSize          = hemiGvisorRingDataOffset + hemiGvisorRingEntries*hemiGvisorRingDataStride
	hemiGvisorRingBatchBytes       = hemiGvisorRingEntries * hemiGvisorRingSlotBytes
	// Small portal operations are cheaper through the legacy ioctl, which
	// avoids ring lane acquisition and descriptor validation. This threshold
	// keeps syscall metadata and futex-adjacent copies off the batching path.
	hemiGvisorRingMinBytes = 256
)

var hemiGvisorZeroBuffer [hemiGvisorRingBatchBytes]byte

var _ platform.AddressSpaceIOIter = (*subprocess)(nil)

type hemiGvisorRingEnterFunc func(int32, *linux.HemiGvisorRingEnter) unix.Errno

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
	file  *fd.FD
	fd    int32
	lanes chan *hemiGvisorRingLane
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
	state := &hemiGvisorDeviceState{
		file: deviceFile,
		fd:   int32(deviceFile.FD()),
	}
	state.lanes = hemiGvisorSetupRingLanes(state.fd)

	hemiGvisorDevice.Lock()
	defer hemiGvisorDevice.Unlock()

	hemiGvisorDevice.state = state
}

func hemiGvisorCurrentDevice() *hemiGvisorDeviceState {
	hemiGvisorDevice.Lock()
	defer hemiGvisorDevice.Unlock()
	return hemiGvisorDevice.state
}

func hemiGvisorDeviceFD() (int32, bool) {
	state := hemiGvisorCurrentDevice()
	if state != nil && state.fd >= 0 {
		return state.fd, true
	}
	return -1, false
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
	setup := linux.HemiGvisorRingSetup{ABIVersion: linux.HEMI_GVISOR_RING_ABI}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(deviceFD), uintptr(linux.HEMI_GVISOR_SETUP_RING),
		uintptr(unsafe.Pointer(&setup)), 0, 0, 0)
	if errno != 0 {
		return nil, errno
	}
	if setup.ABIVersion != linux.HEMI_GVISOR_RING_ABI || setup.Flags != 0 ||
		setup.RingID == 0 || setup.Entries != hemiGvisorRingEntries ||
		setup.DescriptorOffset != hemiGvisorRingDescriptorOffset ||
		setup.DescriptorSize != hemiGvisorRingDescriptorSize ||
		setup.DataOffset != hemiGvisorRingDataOffset ||
		setup.DataStride != hemiGvisorRingDataStride ||
		setup.MaxBytes != hemiGvisorRingBatchBytes ||
		setup.MmapSize != hemiGvisorRingMapSize ||
		setup.MmapOffset%uint64(hostarch.PageSize) != 0 ||
		uint64(uintptr(setup.MmapOffset)) != setup.MmapOffset ||
		uint64(uintptr(setup.MmapSize)) != setup.MmapSize {
		return nil, fmt.Errorf("unsupported HEMI gVisor ring geometry: %+v", setup)
	}

	mapping, err := memutil.MapSlice(
		0, uintptr(setup.MmapSize), unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED, uintptr(uint32(deviceFD)), uintptr(setup.MmapOffset))
	if err != nil {
		return nil, err
	}
	header := (*linux.HemiGvisorRingHeader)(unsafe.Pointer(&mapping[0]))
	if header.Magic != linux.HEMI_GVISOR_RING_MAGIC ||
		header.ABIVersion != linux.HEMI_GVISOR_RING_ABI ||
		header.HeaderSize != hemiGvisorRingHeaderSize ||
		header.RingID != setup.RingID || header.Entries != setup.Entries ||
		header.DescriptorOffset != setup.DescriptorOffset ||
		header.DescriptorSize != setup.DescriptorSize ||
		header.DataOffset != setup.DataOffset ||
		header.DataStride != setup.DataStride ||
		header.MaxBytes != setup.MaxBytes || header.Features != setup.Features ||
		header.Reserved != 0 {
		_ = memutil.UnmapSlice(mapping)
		return nil, fmt.Errorf("HEMI gVisor ring header does not match setup: header=%+v setup=%+v", *header, setup)
	}
	return &hemiGvisorRingLane{ringID: setup.RingID, mapping: mapping}, nil
}

func hemiGvisorRawRingEnter(deviceFD int32, enter *linux.HemiGvisorRingEnter) unix.Errno {
	return hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(deviceFD), uintptr(linux.HEMI_GVISOR_ENTER_RING),
		uintptr(unsafe.Pointer(enter)), 0, 0, 0)
}

func (l *hemiGvisorRingLane) descriptor(index int) *linux.HemiGvisorRingDescriptor {
	offset := hemiGvisorRingDescriptorOffset + index*hemiGvisorRingDescriptorSize
	return (*linux.HemiGvisorRingDescriptor)(unsafe.Pointer(&l.mapping[offset]))
}

func (l *hemiGvisorRingLane) data(index, length int) []byte {
	offset := hemiGvisorRingDataOffset + index*hemiGvisorRingDataStride
	return l.mapping[offset : offset+length]
}

func (l *hemiGvisorRingLane) transfer(deviceFD int32, mmHandle uint64, addr hostarch.Addr, data []byte, op uint16, enterFn hemiGvisorRingEnterFunc) (int, error) {
	return l.transferData(deviceFD, mmHandle, addr, data, op, true, enterFn)
}

// transferInPlace transfers data already stored in, or to be consumed directly
// from, the lane's shared data area. Keeping the platform bounce buffer as the
// safemem Reader/Writer buffer avoids copying through a second Go slice.
func (l *hemiGvisorRingLane) transferInPlace(deviceFD int32, mmHandle uint64, addr hostarch.Addr, data []byte, op uint16, enterFn hemiGvisorRingEnterFunc) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if len(data) > hemiGvisorRingBatchBytes || &data[0] != &l.mapping[hemiGvisorRingDataOffset] {
		return 0, fmt.Errorf("HEMI gVisor in-place ring transfer received a non-lane buffer")
	}
	return l.transferData(deviceFD, mmHandle, addr, data, op, false, enterFn)
}

func (l *hemiGvisorRingLane) transferData(deviceFD int32, mmHandle uint64, addr hostarch.Addr, data []byte, op uint16, bounce bool, enterFn hemiGvisorRingEnterFunc) (int, error) {
	var done int
	for done < len(data) {
		batchLen := min(len(data)-done, hemiGvisorRingBatchBytes)
		count := (batchLen + hemiGvisorRingSlotBytes - 1) / hemiGvisorRingSlotBytes
		batchAddr := addr + hostarch.Addr(done)

		var described int
		for i := 0; i < count; i++ {
			length := min(batchLen-described, hemiGvisorRingSlotBytes)
			*l.descriptor(i) = linux.HemiGvisorRingDescriptor{
				Addr: uint64(batchAddr + hostarch.Addr(described)),
				Len:  uint32(length),
				Op:   op,
			}
			if bounce && op == linux.HEMI_GVISOR_RING_OP_WRITE {
				copy(l.data(i, length), data[done+described:done+described+length])
			}
			described += length
		}

		enter := linux.HemiGvisorRingEnter{
			RingID:   l.ringID,
			MMHandle: mmHandle,
			Count:    uint32(count),
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
			if bounce && op == linux.HEMI_GVISOR_RING_OP_READ && n != 0 {
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

func (d *hemiGvisorDeviceState) tryRingTransfer(mmHandle uint64, addr hostarch.Addr, data []byte, op uint16) (int, error, bool) {
	if d == nil || d.lanes == nil || !hemiGvisorUseRing(len(data)) {
		return 0, nil, false
	}
	select {
	case lane := <-d.lanes:
		n, err := lane.transfer(d.fd, mmHandle, addr, data, op, hemiGvisorRawRingEnter)
		d.lanes <- lane
		return n, err, true
	default:
		return 0, nil, false
	}
}

func (s *subprocess) hemiGvisorInitAddressSpace() error {
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
	if s.hemiGvisorMMHandle != 0 && s.hemiGvisorDevice != nil && s.hemiGvisorDevice != device {
		return fmt.Errorf("HEMI gVisor mm handle %d belongs to a different device instance", s.hemiGvisorMMHandle)
	}
	s.hemiGvisorDevice = device
	s.hemiGvisorTGID = int32(t.thread.tgid)
	if err := s.hemiGvisorResetMMLocked(); err != nil {
		s.hemiGvisorTGID = 0
		return err
	}
	if err := s.hemiGvisorBindAtomicPortalLocked(); err != nil {
		s.hemiGvisorTGID = 0
		return err
	}
	return nil
}

func (s *subprocess) hemiGvisorReleaseAddressSpace() {
	s.hemiGvisorPortalMu.Lock()
	defer s.hemiGvisorPortalMu.Unlock()
	s.hemiGvisorTGID = 0
}

// hemiGvisorDestroyAddressSpace releases resources that intentionally persist
// while a live subprocess is pooled for reuse.
func (s *subprocess) hemiGvisorDestroyAddressSpace() {
	s.hemiGvisorPortalMu.Lock()
	portal := s.hemiGvisorAtomicPortal
	s.hemiGvisorAtomicPortal = nil
	s.hemiGvisorAtomicPortalBindAttempted = false
	s.hemiGvisorTGID = 0
	s.hemiGvisorPortalMu.Unlock()
	if portal != nil {
		_ = portal.Close()
	}
}

// hemiGvisorResetMMLocked resets s's Host-managed address-space state.
//
// Preconditions: s.hemiGvisorPortalMu is locked.
func (s *subprocess) hemiGvisorResetMMLocked() error {
	device := s.hemiGvisorDevice
	if device == nil {
		return nil
	}
	if s.hemiGvisorTGID <= 0 {
		return fmt.Errorf("HEMI gVisor reset has no target subprocess")
	}

	req := linux.HemiGvisorResetMM{MMHandle: s.hemiGvisorMMHandle}
	if req.MMHandle == 0 {
		req.TargetTGID = s.hemiGvisorTGID
	}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(device.fd), uintptr(linux.HEMI_GVISOR_RESET_MM),
		uintptr(unsafe.Pointer(&req)), 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("HEMI gVisor reset mm ioctl for tgid %d: %w",
			s.hemiGvisorTGID, errno)
	}
	if req.MMHandle == 0 {
		return fmt.Errorf("HEMI gVisor reset mm ioctl returned an empty handle")
	}
	s.hemiGvisorMMHandle = req.MMHandle
	return nil
}

// hemiGvisorBindAtomicPortalLocked pins the Host mm behind the persistent
// handle once. Binding is an optional optimization: if the adaptor rejects it
// or cannot allocate the portal, atomic operations retain the handle-based
// ioctl fallback.
//
// Preconditions: s.hemiGvisorPortalMu is locked.
func (s *subprocess) hemiGvisorBindAtomicPortalLocked() error {
	if s.hemiGvisorAtomicPortal != nil || s.hemiGvisorAtomicPortalBindAttempted {
		return nil
	}
	device := s.hemiGvisorDevice
	if device == nil || s.hemiGvisorMMHandle == 0 {
		return nil
	}
	s.hemiGvisorAtomicPortalBindAttempted = true
	req := linux.HemiGvisorBindMM{
		MMHandle: s.hemiGvisorMMHandle,
		PortalFD: -1,
	}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(device.fd), uintptr(linux.HEMI_GVISOR_BIND_MM),
		uintptr(unsafe.Pointer(&req)), 0, 0, 0)
	if errno != 0 {
		return nil
	}
	if req.MMHandle != s.hemiGvisorMMHandle || req.Flags != 0 || req.PortalFD < 0 {
		if req.PortalFD >= 0 {
			_ = unix.Close(int(req.PortalFD))
		}
		return fmt.Errorf("HEMI gVisor bind mm ioctl returned invalid binding: %+v", req)
	}
	s.hemiGvisorAtomicPortal = fd.New(int(req.PortalFD))
	return nil
}

// ForkAddressSpaceFrom implements platform.AddressSpaceForker. It replaces
// this subprocess's empty or pooled HEMI state with a COW fork of source.
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
	if !parent.hemiGvisorActive() || !s.hemiGvisorActive() {
		return fmt.Errorf("HEMI gVisor fork has invalid parent/child handle %d/%d",
			parent.hemiGvisorMMHandle, s.hemiGvisorMMHandle)
	}

	req := linux.HemiGvisorForkMM{
		ParentMMHandle: parent.hemiGvisorMMHandle,
		ChildMMHandle:  s.hemiGvisorMMHandle,
	}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(s.hemiGvisorDevice.fd), uintptr(linux.HEMI_GVISOR_FORK_MM),
		uintptr(unsafe.Pointer(&req)), 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("HEMI gVisor fork mm ioctl for parent/child handle %d/%d: %w",
			parent.hemiGvisorMMHandle, s.hemiGvisorMMHandle, errno)
	}
	return nil
}

func hemiGvisorLockForkPortals(parent, child *subprocess) func() {
	if parent == child {
		parent.hemiGvisorPortalMu.Lock()
		return parent.hemiGvisorPortalMu.Unlock
	}
	first, second := parent, child
	if first.hemiGvisorMMHandle > second.hemiGvisorMMHandle ||
		(first.hemiGvisorMMHandle == second.hemiGvisorMMHandle &&
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
	return s.hemiGvisorTGID > 0 && s.hemiGvisorMMHandle != 0
}

func hemiGvisorContainsUserMem(addr hostarch.Addr, length uint64) bool {
	if length == 0 {
		return true
	}
	start := uint64(addr)
	end := start + length
	return start >= linux.HEMI_GVISOR_VMAR_START &&
		end >= start && end <= linux.HEMI_GVISOR_VMAR_END
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

	req := linux.HemiGvisorUserMem{
		Addr:     uint64(addr),
		Len:      uint64(len(data)),
		UserBuf:  uint64(uintptr(unsafe.Pointer(&data[0]))),
		MMHandle: s.hemiGvisorMMHandle,
	}
	cmd := linux.HEMI_GVISOR_READ_USER
	if write {
		cmd = linux.HEMI_GVISOR_WRITE_USER
	}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(device.fd), uintptr(cmd),
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
	start := hostarch.Addr(linux.HEMI_GVISOR_VMAR_START)
	end := hostarch.Addr(linux.HEMI_GVISOR_VMAR_END)
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
		return device, lane, s.hemiGvisorMMHandle, nil
	default:
		return nil, nil, 0, platform.AddressSpaceIOUnavailable{}
	}
}

func (s *subprocess) hemiGvisorTransferRingInPlace(device *hemiGvisorDeviceState, lane *hemiGvisorRingLane, mmHandle uint64, addr hostarch.Addr, data []byte, op uint16, enterFn hemiGvisorRingEnterFunc) (int, error) {
	s.hemiGvisorPortalMu.Lock()
	defer s.hemiGvisorPortalMu.Unlock()
	if !s.hemiGvisorActive() || s.hemiGvisorDevice != device || s.hemiGvisorMMHandle != mmHandle {
		return 0, &platform.AddressSpaceIOStreamError{Err: fmt.Errorf("HEMI gVisor address space changed during ring transfer")}
	}
	n, err := lane.transferInPlace(device.fd, mmHandle, addr, data, op, enterFn)
	if err != nil {
		return n, &platform.AddressSpaceIOStreamError{Err: err}
	}
	return n, nil
}

// CopyOutFromIter implements platform.AddressSpaceIOIter.CopyOutFromIter. The
// Reader fills the ring lane directly; ENTER_RING then copies from that same
// shared buffer into HEMI-managed application memory.
func (s *subprocess) CopyOutFromIter(ars hostarch.AddrRangeSeq, src safemem.Reader) (int64, error) {
	return s.copyOutFromIter(ars, src, hemiGvisorRawRingEnter)
}

func (s *subprocess) copyOutFromIter(ars hostarch.AddrRangeSeq, src safemem.Reader, enterFn hemiGvisorRingEnterFunc) (int64, error) {
	device, lane, mmHandle, err := s.hemiGvisorAcquireRingLane(ars)
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
			copied, targetErr := s.hemiGvisorTransferRingInPlace(
				device, lane, mmHandle, ar.Start, buf[:n], linux.HEMI_GVISOR_RING_OP_WRITE, enterFn)
			done += int64(copied)
			ars = ars.DropFirst(copied)
			if targetErr != nil {
				return done, targetErr
			}
			if copied != n {
				return done, &platform.AddressSpaceIOStreamError{Err: fmt.Errorf("HEMI gVisor ring copied only %d/%d bytes without an error", copied, n)}
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
func (s *subprocess) CopyInToIter(ars hostarch.AddrRangeSeq, dst safemem.Writer) (int64, error) {
	return s.copyInToIter(ars, dst, hemiGvisorRawRingEnter)
}

func (s *subprocess) copyInToIter(ars hostarch.AddrRangeSeq, dst safemem.Writer, enterFn hemiGvisorRingEnterFunc) (int64, error) {
	device, lane, mmHandle, err := s.hemiGvisorAcquireRingLane(ars)
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
			device, lane, mmHandle, ar.Start, buf[:want], linux.HEMI_GVISOR_RING_OP_READ, enterFn)
		if copied == 0 {
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
		access |= linux.HEMI_GVISOR_USER_ACCESS_READ
	}
	if at.Write {
		access |= linux.HEMI_GVISOR_USER_ACCESS_WRITE
	}
	if access == 0 || at.Execute {
		return 0, platform.AddressSpaceIOUnavailable{}
	}

	req := linux.HemiGvisorProbeUser{
		Addr:     uint64(addr),
		Len:      length,
		MMHandle: s.hemiGvisorMMHandle,
		Access:   access,
	}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(device.fd), uintptr(linux.HEMI_GVISOR_PROBE_USER),
		uintptr(unsafe.Pointer(&req)), 0, 0, 0)
	if errno != 0 {
		return req.Done, fmt.Errorf("HEMI gVisor probe user ioctl: %w", errno)
	}
	if req.Result != 0 {
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
		Start: hostarch.Addr(linux.HEMI_GVISOR_VMAR_START),
		End:   hostarch.Addr(linux.HEMI_GVISOR_VMAR_END),
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
			s.hemiGvisorMMHandle, addr, dst, linux.HEMI_GVISOR_RING_OP_READ); ok {
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
			s.hemiGvisorMMHandle, addr, src, linux.HEMI_GVISOR_RING_OP_WRITE); ok {
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
	return s.hemiGvisorAtomicUint32(addr, linux.HEMI_GVISOR_ATOMIC_U32_SWAP, 0, value)
}

func (s *subprocess) CompareAndSwapUint32(addr hostarch.Addr, old, value uint32) (uint32, error) {
	return s.hemiGvisorAtomicUint32(addr, linux.HEMI_GVISOR_ATOMIC_U32_CMPXCHG, old, value)
}

func (s *subprocess) LoadUint32(addr hostarch.Addr) (uint32, error) {
	return s.hemiGvisorAtomicUint32(addr, linux.HEMI_GVISOR_ATOMIC_U32_LOAD, 0, 0)
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

	req := linux.HemiGvisorAtomicU32{
		Addr:     uint64(addr),
		MMHandle: s.hemiGvisorMMHandle,
		Op:       op,
		Old:      old,
		New:      new,
	}
	atomicFD := device.fd
	if s.hemiGvisorAtomicPortal != nil {
		atomicFD = int32(s.hemiGvisorAtomicPortal.FD())
	}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(atomicFD), uintptr(linux.HEMI_GVISOR_ATOMIC_U32),
		uintptr(unsafe.Pointer(&req)), 0, 0, 0)
	if errno == 0 {
		return req.Value, nil
	}
	if errno == unix.EFAULT {
		return 0, platform.SegmentationFault{Addr: addr}
	}
	return 0, fmt.Errorf("HEMI gVisor atomic u32 ioctl: %w", errno)
}

type hemiGvisorTask interface {
	GetFile(int32) *vfs.FileDescription
}

func (s *subprocess) prepareHemiGvisorMapFile(ctx context.Context, c *platformContext, ac *arch.Context64) {
	if runtime.GOARCH != "amd64" || ac.SyscallNo() != unix.SYS_MMAP {
		return
	}
	args := ac.SyscallArgs()
	prot := args[2].Int()
	flags := args[3].Int()
	if flags&linux.MAP_ANONYMOUS != 0 {
		return
	}
	// Device state is immutable after publication and remains referenced by the
	// subprocess across pooling, so it is safe to use this snapshot after
	// dropping the portal lock.
	s.hemiGvisorPortalMu.Lock()
	device := s.hemiGvisorDevice
	s.hemiGvisorPortalMu.Unlock()
	if device == nil {
		return
	}
	task, ok := ctx.(hemiGvisorTask)
	if !ok {
		return
	}
	hostFD, hostOffset, err := hemiGvisorLookupHostFile(ctx, task, prot, flags, args)
	if err != nil {
		return
	}
	req := linux.HemiGvisorMapFile{
		Addr:        args[0].Uint64(),
		Len:         args[1].Uint64(),
		Prot:        args[2].Uint64(),
		Flags:       args[3].Uint64(),
		GuestFD:     int64(args[4].Int()),
		GuestOffset: args[5].Uint64(),
		HostFD:      int64(hostFD),
		HostOffset:  hostOffset,
	}
	s.hemiGvisorMapFileIoctl(device.fd, req)
}

func (s *subprocess) hemiGvisorMapFileIoctl(devFD int32, req linux.HemiGvisorMapFile) {
	s.syscallThreadMu.Lock()
	defer s.syscallThreadMu.Unlock()

	t := s.syscallThread
	if t == nil {
		return
	}
	t.sentryMessage.hemiMapFile = req
	reqAddr := t.stubAddr + unsafe.Offsetof(syscallSentryMessage{}.hemiMapFile)
	_, _ = t.syscall(unix.SYS_IOCTL,
		arch.SyscallArgument{Value: uintptr(uint32(devFD))},
		arch.SyscallArgument{Value: uintptr(linux.HEMI_GVISOR_MAP_FILE)},
		arch.SyscallArgument{Value: reqAddr})
}

func hemiGvisorLookupHostFile(ctx context.Context, task hemiGvisorTask, prot, flags int32, args arch.SyscallArguments) (int, uint64, error) {
	private := flags&linux.MAP_PRIVATE != 0
	shared := flags&linux.MAP_SHARED != 0
	if private == shared {
		return -1, 0, linuxerr.EINVAL
	}

	length, ok := hostarch.Addr(args[1].Uint64()).RoundUp()
	if !ok {
		return -1, 0, linuxerr.ENOMEM
	}
	if length == 0 {
		return -1, 0, linuxerr.EINVAL
	}

	fd := args[4].Int()
	file := task.GetFile(fd)
	if file == nil {
		return -1, 0, linuxerr.EBADF
	}
	defer file.DecRef(ctx)

	if !file.IsReadable() {
		return -1, 0, linuxerr.EACCES
	}

	opts := memmap.MMapOpts{
		Length:   uint64(length),
		Offset:   args[5].Uint64(),
		Addr:     args[0].Pointer(),
		Fixed:    flags&linux.MAP_FIXED != 0,
		Unmap:    flags&linux.MAP_FIXED != 0,
		Map32Bit: flags&linux.MAP_32BIT != 0,
		Private:  private,
		Perms: hostarch.AccessType{
			Read:    linux.PROT_READ&prot != 0,
			Write:   linux.PROT_WRITE&prot != 0,
			Execute: linux.PROT_EXEC&prot != 0,
		},
		MaxPerms:  hostarch.AnyAccess,
		GrowsDown: linux.MAP_GROWSDOWN&flags != 0,
		Stack:     linux.MAP_STACK&flags != 0,
	}
	if linux.MAP_POPULATE&flags != 0 {
		opts.PlatformEffect = memmap.PlatformEffectCommit
	}
	if linux.MAP_LOCKED&flags != 0 {
		opts.MLockMode = memmap.MLockEager
	}
	defer func() {
		if opts.MappingIdentity != nil {
			opts.MappingIdentity.DecRef(ctx)
		}
	}()

	if shared && !file.IsWritable() {
		opts.MaxPerms.Write = false
	}
	if shared {
		if seals, err := tmpfs.GetSeals(file); err == nil && seals&linux.F_SEAL_WRITE != 0 {
			if opts.Perms.Write {
				return -1, 0, linuxerr.EPERM
			}
			opts.MaxPerms.Write = false
		}
	}
	if file.Mount().MountFlags()&linux.ST_NOEXEC != 0 {
		if opts.Perms.Execute {
			return -1, 0, linuxerr.EPERM
		}
		opts.MaxPerms.Execute = false
	}
	if err := file.ConfigureMMap(ctx, &opts); err != nil {
		return -1, 0, err
	}
	return hemiGvisorHostFile(ctx, &opts)
}

func hemiGvisorHostFile(ctx context.Context, opts *memmap.MMapOpts) (int, uint64, error) {
	if opts.Mappable == nil {
		return -1, 0, linuxerr.ENODEV
	}
	end := opts.Offset + opts.Length
	if end < opts.Offset {
		return -1, 0, linuxerr.EOVERFLOW
	}
	mr := memmap.MappableRange{Start: opts.Offset, End: end}
	probeEnd := opts.Offset + uint64(hostarch.PageSize)
	if probeEnd < opts.Offset || probeEnd > end {
		probeEnd = end
	}
	probe := memmap.MappableRange{Start: opts.Offset, End: probeEnd}

	at := opts.Perms
	if opts.Private {
		at.Read = true
		at.Write = false
	}
	if !at.Any() {
		at.Read = true
	}

	ts, err := opts.Mappable.Translate(ctx, probe, mr, at)
	if len(ts) == 0 {
		if err != nil {
			return -1, 0, err
		}
		return -1, 0, linuxerr.ENODEV
	}
	if !ts[0].Source.Contains(probe.Start) {
		return -1, 0, linuxerr.ENODEV
	}

	hostOffset := ts[0].Offset + (mr.Start - ts[0].Source.Start)
	fr := ts[0].FileRange()
	ts[0].File.IncRef(fr, pgalloc.MemoryCgroupIDFromContext(ctx))
	defer ts[0].File.DecRef(fr)

	hostFD, err := ts[0].File.DataFD(fr)
	if err != nil {
		return -1, 0, err
	}
	if hostFD < 0 {
		return -1, 0, linuxerr.ENODEV
	}
	return hostFD, hostOffset, nil
}
