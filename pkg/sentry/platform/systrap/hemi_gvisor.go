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
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

const hemiGvisorDevicePath = "/dev/hemi_gvisor"

const hemiGvisorUserMemMax = 16 * hostarch.PageSize

var hemiGvisorDevice = struct {
	sync.Mutex
	file *fd.FD
	fd   int32
}{
	fd: -1,
}

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

	hemiGvisorDevice.Lock()
	defer hemiGvisorDevice.Unlock()

	hemiGvisorDevice.file = deviceFile
	hemiGvisorDevice.fd = int32(deviceFile.FD())
}

func hemiGvisorDeviceFD() (int32, bool) {
	hemiGvisorDevice.Lock()
	defer hemiGvisorDevice.Unlock()

	if hemiGvisorDevice.fd >= 0 {
		return hemiGvisorDevice.fd, true
	}
	return -1, false
}

func (s *subprocess) hemiGvisorInitAddressSpace() error {
	if _, ok := hemiGvisorDeviceFD(); !ok {
		return nil
	}

	s.syscallThreadMu.Lock()
	t := s.syscallThread
	s.syscallThreadMu.Unlock()
	if t == nil || t.thread == nil {
		return fmt.Errorf("HEMI gVisor subprocess has no host thread")
	}

	s.hemiGvisorTGID = int32(t.thread.tgid)
	return s.hemiGvisorResetMM()
}

func (s *subprocess) hemiGvisorReleaseAddressSpace() {
	s.hemiGvisorTGID = 0
}

func (s *subprocess) hemiGvisorResetMM() error {
	deviceFD, ok := hemiGvisorDeviceFD()
	if !ok {
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
		unix.SYS_IOCTL, uintptr(deviceFD), uintptr(linux.HEMI_GVISOR_RESET_MM),
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

// ForkAddressSpaceFrom implements platform.AddressSpaceForker. It replaces
// this subprocess's empty or pooled HEMI state with a COW fork of source.
func (s *subprocess) ForkAddressSpaceFrom(source platform.AddressSpace) error {
	deviceFD, ok := hemiGvisorDeviceFD()
	if !ok {
		return nil
	}
	parent, ok := source.(*subprocess)
	if !ok {
		return fmt.Errorf("HEMI gVisor fork source has type %T", source)
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
		unix.SYS_IOCTL, uintptr(deviceFD), uintptr(linux.HEMI_GVISOR_FORK_MM),
		uintptr(unsafe.Pointer(&req)), 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("HEMI gVisor fork mm ioctl for parent/child handle %d/%d: %w",
			parent.hemiGvisorMMHandle, s.hemiGvisorMMHandle, errno)
	}
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
	deviceFD, ok := hemiGvisorDeviceFD()
	if !ok || !s.hemiGvisorActive() {
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
		unix.SYS_IOCTL, uintptr(deviceFD), uintptr(cmd),
		uintptr(unsafe.Pointer(&req)), 0, 0, 0)
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

// AddressSpaceIOReadIgnoresPermissions reports that HEMI CopyIn reads through
// HEMI's authoritative page tables and can service instruction-emulation reads.
func (s *subprocess) AddressSpaceIOReadIgnoresPermissions() bool {
	return s.hemiGvisorActive()
}

// EnsureAccess faults in and validates a HEMI-managed user range without
// consulting the sentry's VMA/PMA metadata.
func (s *subprocess) EnsureAccess(addr hostarch.Addr, length uint64, at hostarch.AccessType) (uint64, error) {
	if !hemiGvisorContainsUserMem(addr, length) {
		return 0, platform.AddressSpaceIOUnavailable{}
	}
	deviceFD, ok := hemiGvisorDeviceFD()
	if !ok || !s.hemiGvisorActive() {
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
		unix.SYS_IOCTL, uintptr(deviceFD), uintptr(linux.HEMI_GVISOR_PROBE_USER),
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
	var done int
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
	var done int
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
	zero := make([]byte, min(toZero, hostarch.PageSize))
	var done uintptr
	for done < toZero {
		length := min(toZero-done, uintptr(len(zero)))
		n, err := s.CopyOut(addr+hostarch.Addr(done), zero[:length])
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
	deviceFD, ok := hemiGvisorDeviceFD()
	if !ok || !s.hemiGvisorActive() {
		return 0, platform.AddressSpaceIOUnavailable{}
	}

	req := linux.HemiGvisorAtomicU32{
		Addr:     uint64(addr),
		MMHandle: s.hemiGvisorMMHandle,
		Op:       op,
		Old:      old,
		New:      new,
	}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_IOCTL, uintptr(deviceFD), uintptr(linux.HEMI_GVISOR_ATOMIC_U32),
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
	devFD, ok := hemiGvisorDeviceFD()
	if !ok {
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
	s.hemiGvisorMapFileIoctl(int32(devFD), req)
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
