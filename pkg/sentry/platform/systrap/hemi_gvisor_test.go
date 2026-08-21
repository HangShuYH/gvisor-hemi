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
	"bytes"
	"errors"
	"math"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

type hemiGvisorTestMapping struct {
	refs         int
	mapped       bool
	identity     platform.PrivateFileIdentity
	translations []memmap.Translation
	translateErr error
}

func (i *hemiGvisorTestMapping) IncRef() {
	i.refs++
}

func (i *hemiGvisorTestMapping) DecRef(context.Context) {
	i.refs--
}

func (i *hemiGvisorTestMapping) InodeIdentity() platform.PrivateFileIdentity {
	return i.identity
}

func (i *hemiGvisorTestMapping) AddMapping(context.Context, uint64, uint64) error {
	i.mapped = true
	return nil
}

func (i *hemiGvisorTestMapping) RemoveMapping(context.Context) {
	i.mapped = false
}

func (i *hemiGvisorTestMapping) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	if err := memmap.CheckTranslateResult(required, optional, at, i.translations, i.translateErr); err != nil {
		return nil, err
	}
	for _, t := range i.translations {
		t.File.IncRef(t.FileRange(), 0)
	}
	return i.translations, i.translateErr
}

type hemiGvisorTestFile struct {
	memmap.DefaultMemoryType
	memmap.NoBufferedIOFallback
	refs int
	fd   int
}

func (f *hemiGvisorTestFile) IncRef(memmap.FileRange, uint32) {
	f.refs++
}

func (f *hemiGvisorTestFile) DecRef(memmap.FileRange) {
	f.refs--
}

func (f *hemiGvisorTestFile) MapInternal(memmap.FileRange, hostarch.AccessType) (safemem.BlockSeq, error) {
	return safemem.BlockSeq{}, nil
}

func (f *hemiGvisorTestFile) DataFD(memmap.FileRange) (int, error) {
	return f.fd, nil
}

func (f *hemiGvisorTestFile) FD() int {
	return f.fd
}

func TestHemiGvisorAllocateMMID(t *testing.T) {
	device := &hemiGvisorDeviceState{}
	for _, want := range []uint64{1, 2} {
		got, err := device.allocateMMID()
		if err != nil {
			t.Fatalf("allocateMMID: %v", err)
		}
		if got != want {
			t.Fatalf("allocateMMID = %d, want %d", got, want)
		}
	}

	device.nextMMID = math.MaxUint64
	if got, err := device.allocateMMID(); err == nil || got != 0 {
		t.Fatalf("exhausted allocateMMID = (%d, %v), want (0, error)", got, err)
	}
}

func TestHemiGvisorFileTokenOwnership(t *testing.T) {
	ctx := context.Background()
	provider := &hemiGvisorTestMapping{}
	device := &hemiGvisorDeviceState{}

	if err := provider.AddMapping(ctx, hostarch.PageSize, 0); err != nil {
		t.Fatalf("AddMapping: %v", err)
	}
	fileToken, inodeToken, err := device.registerFileTokens(provider)
	if err != nil {
		t.Fatalf("registerFileTokens: %v", err)
	}
	if fileToken == 0 || inodeToken == 0 || fileToken == inodeToken {
		t.Fatalf("registerFileTokens returned invalid tokens %d/%d", fileToken, inodeToken)
	}
	if got := provider.refs; got != 2 {
		t.Fatalf("provider refs after register = %d, want 2", got)
	}
	if got := len(device.tokens); got != 2 {
		t.Fatalf("registry length after register = %d, want 2", got)
	}

	if err := device.releaseToken(ctx, fileToken, linux.HEMI_USERSPACE_RELEASE_FILE, 1); err != nil {
		t.Fatalf("release file token: %v", err)
	}
	if got := provider.refs; got != 1 {
		t.Fatalf("provider refs after file release = %d, want 1", got)
	}
	if provider.mapped {
		t.Fatal("provider mapping remained after file release")
	}
	if err := device.releaseToken(ctx, inodeToken, linux.HEMI_USERSPACE_RELEASE_INODE, 1); err != nil {
		t.Fatalf("release inode token: %v", err)
	}
	if got := provider.refs; got != 0 {
		t.Fatalf("provider refs after inode release = %d, want 0", got)
	}
	if got := len(device.tokens); got != 0 {
		t.Fatalf("registry length after release = %d, want 0", got)
	}
	if got := len(device.inodes); got != 0 {
		t.Fatalf("inode registry length after release = %d, want 0", got)
	}
	if err := device.releaseToken(ctx, fileToken, linux.HEMI_USERSPACE_RELEASE_FILE, 1); err == nil {
		t.Fatal("duplicate file release unexpectedly succeeded")
	}
}

func TestHemiGvisorInodeTokenSharedByMappable(t *testing.T) {
	ctx := context.Background()
	identity := platform.PrivateFileIdentity{DeviceID: 12, InodeID: 34}
	first := &hemiGvisorTestMapping{identity: identity}
	second := &hemiGvisorTestMapping{identity: identity}
	device := &hemiGvisorDeviceState{}
	for _, provider := range []*hemiGvisorTestMapping{first, second} {
		if err := provider.AddMapping(ctx, hostarch.PageSize, 0); err != nil {
			t.Fatalf("AddMapping: %v", err)
		}
	}

	firstFile, firstInode, err := device.registerFileTokens(first)
	if err != nil {
		t.Fatalf("register first file tokens: %v", err)
	}
	secondFile, secondInode, err := device.registerFileTokens(second)
	if err != nil {
		t.Fatalf("register second file tokens: %v", err)
	}
	if firstFile == secondFile {
		t.Fatalf("file token %d was reused", firstFile)
	}
	if firstInode != secondInode {
		t.Fatalf("inode tokens differ: %d and %d", firstInode, secondInode)
	}

	if err := device.releaseToken(ctx, firstFile, linux.HEMI_USERSPACE_RELEASE_FILE, 1); err != nil {
		t.Fatalf("release first file token: %v", err)
	}
	if err := device.releaseToken(ctx, secondFile, linux.HEMI_USERSPACE_RELEASE_FILE, 1); err != nil {
		t.Fatalf("release second file token: %v", err)
	}
	if err := device.releaseToken(ctx, firstInode, linux.HEMI_USERSPACE_RELEASE_INODE, 2); err != nil {
		t.Fatalf("release shared inode token: %v", err)
	}
	if first.refs != 0 || second.refs != 0 {
		t.Fatalf("provider refs after release = %d/%d, want 0/0", first.refs, second.refs)
	}
	if got := len(device.inodes); got != 0 {
		t.Fatalf("inode registry length after release = %d, want 0", got)
	}
}

func TestHemiGvisorDrainReleaseQueues(t *testing.T) {
	ctx := context.Background()
	provider := &hemiGvisorTestMapping{}
	const queueCount = 2
	mapping := make([]byte, queueCount*linux.HEMI_USERSPACE_RELEASE_QUEUE_STRIDE)
	device := &hemiGvisorDeviceState{
		tokens:         make(map[uint64]hemiGvisorToken),
		releaseMapping: mapping,
		releaseCount:   queueCount,
		releaseStride:  linux.HEMI_USERSPACE_RELEASE_QUEUE_STRIDE,
	}
	if err := provider.AddMapping(ctx, hostarch.PageSize, 0); err != nil {
		t.Fatalf("AddMapping: %v", err)
	}
	fileToken, inodeToken, err := device.registerFileTokens(provider)
	if err != nil {
		t.Fatalf("registerFileTokens: %v", err)
	}
	tokens := []struct {
		token uint64
		kind  uint32
	}{
		{token: fileToken, kind: linux.HEMI_USERSPACE_RELEASE_FILE},
		{token: inodeToken, kind: linux.HEMI_USERSPACE_RELEASE_INODE},
	}
	for queue, token := range tokens {
		offset := queue * linux.HEMI_USERSPACE_RELEASE_QUEUE_STRIDE
		ring := (*linux.HemiUserspaceReleaseRing)(
			unsafe.Pointer(&mapping[offset]))
		ring.Records[0] = linux.HemiUserspaceReleaseRecord{
			Token: token.token,
			Count: 1,
			Type:  token.kind,
		}
		atomic.StoreUint32(&ring.Tail, 1)
	}

	if err := device.drainReleases(ctx); err != nil {
		t.Fatalf("drainReleases: %v", err)
	}
	if got := provider.refs; got != 0 {
		t.Fatalf("provider refs after drain = %d, want 0", got)
	}
	if got := len(device.tokens); got != 0 {
		t.Fatalf("registry length after drain = %d, want 0", got)
	}
	for queue := range tokens {
		offset := queue * linux.HEMI_USERSPACE_RELEASE_QUEUE_STRIDE
		ring := (*linux.HemiUserspaceReleaseRing)(
			unsafe.Pointer(&mapping[offset]))
		if got := atomic.LoadUint32(&ring.Head); got != 1 {
			t.Errorf("queue %d head after drain = %d, want 1", queue, got)
		}
	}
}

func TestHemiGvisorNotifyReleaseDrainOnlyWhenPending(t *testing.T) {
	const queueCount = 2
	mapping := make([]byte, queueCount*linux.HEMI_USERSPACE_RELEASE_QUEUE_STRIDE)
	device := &hemiGvisorDeviceState{
		releaseMapping: mapping,
		releaseCount:   queueCount,
		releaseStride:  linux.HEMI_USERSPACE_RELEASE_QUEUE_STRIDE,
		releaseWake:    make(chan struct{}, 1),
	}

	device.notifyReleaseDrain()
	select {
	case <-device.releaseWake:
		t.Fatal("empty release queues triggered a drain")
	default:
	}

	ring := (*linux.HemiUserspaceReleaseRing)(unsafe.Pointer(
		&mapping[linux.HEMI_USERSPACE_RELEASE_QUEUE_STRIDE]))
	atomic.StoreUint32(&ring.Tail, 1)
	device.notifyReleaseDrain()
	select {
	case <-device.releaseWake:
	default:
		t.Fatal("pending release queue did not trigger a drain")
	}
}

func TestHemiGvisorTranslateFilePages(t *testing.T) {
	const (
		guestOffset = uint64(0x2000)
		hostOffset  = uint64(0x12000)
		pageCount   = uint32(3)
		hostFD      = 37
	)
	file := &hemiGvisorTestFile{fd: hostFD}
	provider := &hemiGvisorTestMapping{
		mapped: true,
		translations: []memmap.Translation{{
			Source: memmap.MappableRange{
				Start: guestOffset,
				End:   guestOffset + uint64(pageCount)*uint64(hostarch.PageSize),
			},
			File:   file,
			Offset: hostOffset,
			Perms:  hostarch.AnyAccess,
		}},
	}
	pages, refs, err := hemiGvisorTranslateFilePages(
		context.Background(), provider, guestOffset, pageCount,
		hostarch.AccessType{Write: true})
	if err != nil {
		t.Fatalf("hemiGvisorTranslateFilePages: %v", err)
	}
	if got := len(pages); got != int(pageCount) {
		t.Fatalf("translated pages = %d, want %d", got, pageCount)
	}
	for i, page := range pages {
		if page.HostFD != hostFD {
			t.Errorf("page %d fd = %d, want %d", i, page.HostFD, hostFD)
		}
		wantOffset := hostOffset + uint64(i)*uint64(hostarch.PageSize)
		if page.HostOffset != wantOffset {
			t.Errorf("page %d offset = %#x, want %#x", i, page.HostOffset, wantOffset)
		}
	}
	if file.refs != 1 {
		t.Fatalf("translated file refs = %d, want 1", file.refs)
	}
	hemiGvisorReleaseFileRanges(refs)
	if file.refs != 0 {
		t.Fatalf("file refs after release = %d, want 0", file.refs)
	}
}

func TestHemiGvisorContainsUserMem(t *testing.T) {
	tests := []struct {
		name   string
		addr   uint64
		length uint64
		want   bool
	}{
		{name: "empty below range", addr: 0, length: 0, want: true},
		{name: "first byte", addr: linux.HEMI_USERSPACE_VMAR_START, length: 1, want: true},
		{name: "last byte", addr: linux.HEMI_USERSPACE_VMAR_END - 1, length: 1, want: true},
		{name: "entire range", addr: linux.HEMI_USERSPACE_VMAR_START, length: linux.HEMI_USERSPACE_VMAR_END - linux.HEMI_USERSPACE_VMAR_START, want: true},
		{name: "below range", addr: linux.HEMI_USERSPACE_VMAR_START - 1, length: 1, want: false},
		{name: "crosses start", addr: linux.HEMI_USERSPACE_VMAR_START - 1, length: 2, want: false},
		{name: "at end", addr: linux.HEMI_USERSPACE_VMAR_END, length: 1, want: false},
		{name: "crosses end", addr: linux.HEMI_USERSPACE_VMAR_END - 1, length: 2, want: false},
		{name: "overflow", addr: math.MaxUint64 - 1, length: 4, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := hemiGvisorContainsUserMem(hostarch.Addr(test.addr), test.length); got != test.want {
				t.Fatalf("hemiGvisorContainsUserMem(%#x, %#x) = %t, want %t", test.addr, test.length, got, test.want)
			}
		})
	}
}

func TestHemiGvisorAddressSpaceIOApplicablePrefix(t *testing.T) {
	const (
		start = hostarch.Addr(linux.HEMI_USERSPACE_VMAR_START)
		end   = hostarch.Addr(linux.HEMI_USERSPACE_VMAR_END)
	)
	tests := []struct {
		name           string
		ar             hostarch.AddrRange
		wantLength     hostarch.Addr
		wantApplicable bool
	}{
		{name: "below range", ar: hostarch.AddrRange{Start: start - 2, End: start - 1}, wantLength: 1},
		{name: "crosses start", ar: hostarch.AddrRange{Start: start - 1, End: start + 1}, wantLength: 1},
		{name: "inside range", ar: hostarch.AddrRange{Start: start, End: start + 1}, wantLength: 1, wantApplicable: true},
		{name: "crosses end", ar: hostarch.AddrRange{Start: end - 1, End: end + 1}, wantLength: 1, wantApplicable: true},
		{name: "above range", ar: hostarch.AddrRange{Start: end, End: end + 1}, wantLength: 1},
	}

	s := subprocess{hemiGvisorTGID: 1, hemiGvisorMMID: 1}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotLength, gotApplicable := s.AddressSpaceIOApplicablePrefix(test.ar)
			if gotLength != test.wantLength || gotApplicable != test.wantApplicable {
				t.Fatalf("AddressSpaceIOApplicablePrefix(%v) = (%d, %t), want (%d, %t)", test.ar, gotLength, gotApplicable, test.wantLength, test.wantApplicable)
			}
		})
	}

	inactive := subprocess{}
	ar := hostarch.AddrRange{Start: start, End: start + 1}
	if gotLength, gotApplicable := inactive.AddressSpaceIOApplicablePrefix(ar); gotLength != ar.Length() || gotApplicable {
		t.Fatalf("inactive AddressSpaceIOApplicablePrefix(%v) = (%d, %t), want (%d, false)", ar, gotLength, gotApplicable, ar.Length())
	}
}

func TestHemiGvisorKeepSyscallUnpatched(t *testing.T) {
	inactive := subprocess{}
	active := subprocess{hemiGvisorTGID: 1, hemiGvisorMMID: 1}
	for _, sysno := range []uintptr{
		unix.SYS_MMAP,
		unix.SYS_MUNMAP,
		unix.SYS_MPROTECT,
		unix.SYS_BRK,
	} {
		if inactive.hemiGvisorKeepSyscallUnpatched(sysno) {
			t.Errorf("inactive HEMI subprocess kept memory syscall %d unpatched", sysno)
		}
		if !active.hemiGvisorKeepSyscallUnpatched(sysno) {
			t.Errorf("active HEMI subprocess allowed memory syscall %d to be patched", sysno)
		}
	}
	for _, sysno := range []uintptr{
		unix.SYS_READ,
		unix.SYS_WRITE,
		unix.SYS_FUTEX,
		unix.SYS_GETPID,
	} {
		if active.hemiGvisorKeepSyscallUnpatched(sysno) {
			t.Errorf("active HEMI subprocess kept non-memory syscall %d unpatched", sysno)
		}
	}
}

func TestHemiGvisorUserMemResult(t *testing.T) {
	const addr = hostarch.Addr(linux.HEMI_USERSPACE_VMAR_START)

	if done, err := hemiGvisorUserMemResult(addr, 8192, 8192, 0); err != nil || done != 8192 {
		t.Fatalf("full result = (%d, %v), want (8192, nil)", done, err)
	}
	if done, err := hemiGvisorUserMemResult(addr, 8192, 4096, 0); err == nil || done != 4096 {
		t.Fatalf("short success = (%d, %v), want (4096, error)", done, err)
	}
	if done, err := hemiGvisorUserMemResult(addr, 8192, 4096, -int32(unix.EFAULT)); done != 4096 {
		t.Fatalf("partial fault progress = %d, want 4096", done)
	} else if fault, ok := err.(platform.SegmentationFault); !ok {
		t.Fatalf("partial fault error = %T(%v), want platform.SegmentationFault", err, err)
	} else if want := addr + 4096; fault.Addr != want {
		t.Fatalf("partial fault address = %#x, want %#x", fault.Addr, want)
	}
	if done, err := hemiGvisorUserMemResult(addr, 8192, 8193, 0); err == nil || done != 0 {
		t.Fatalf("invalid progress = (%d, %v), want (0, error)", done, err)
	}
}

func TestHemiGvisorRingABILayout(t *testing.T) {
	setup := linux.HemiUserspaceRingSetup{}
	if got, want := unsafe.Sizeof(setup), uintptr(16); got != want {
		t.Fatalf("sizeof(HemiUserspaceRingSetup) = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(setup.MmapOffset), uintptr(8); got != want {
		t.Fatalf("offsetof(HemiUserspaceRingSetup.MmapOffset) = %d, want %d", got, want)
	}

	descriptor := linux.HemiUserspaceRingDescriptor{}
	if got, want := unsafe.Sizeof(descriptor), uintptr(64); got != want {
		t.Fatalf("sizeof(HemiUserspaceRingDescriptor) = %d, want %d", got, want)
	}
	for name, got := range map[string]uintptr{
		"Addr":   unsafe.Offsetof(descriptor.Addr),
		"Len":    unsafe.Offsetof(descriptor.Len),
		"Op":     unsafe.Offsetof(descriptor.Op),
		"Flags":  unsafe.Offsetof(descriptor.Flags),
		"Done":   unsafe.Offsetof(descriptor.Done),
		"Result": unsafe.Offsetof(descriptor.Result),
	} {
		want := map[string]uintptr{"Addr": 0, "Len": 8, "Op": 12, "Flags": 14, "Done": 16, "Result": 20}[name]
		if got != want {
			t.Errorf("offsetof(HemiUserspaceRingDescriptor.%s) = %d, want %d", name, got, want)
		}
	}

	enter := linux.HemiUserspaceRingEnter{}
	if got, want := unsafe.Sizeof(enter), uintptr(24); got != want {
		t.Fatalf("sizeof(HemiUserspaceRingEnter) = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(enter.Reserved), uintptr(20); got != want {
		t.Fatalf("offsetof(HemiUserspaceRingEnter.Reserved) = %d, want %d", got, want)
	}

	alloc := linux.HemiUserspaceAllocMM{}
	if got, want := unsafe.Sizeof(alloc), uintptr(16); got != want {
		t.Fatalf("sizeof(HemiUserspaceAllocMM) = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(alloc.MMID), uintptr(0); got != want {
		t.Fatalf("offsetof(HemiUserspaceAllocMM.MMID) = %d, want %d", got, want)
	}

	fork := linux.HemiUserspaceForkMM{}
	if got, want := unsafe.Sizeof(fork), uintptr(24); got != want {
		t.Fatalf("sizeof(HemiUserspaceForkMM) = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(fork.ChildMMID), uintptr(8); got != want {
		t.Fatalf("offsetof(HemiUserspaceForkMM.ChildMMID) = %d, want %d", got, want)
	}
	if got, want := unsafe.Sizeof(linux.HemiUserspaceFreeMM{}), uintptr(8); got != want {
		t.Fatalf("sizeof(HemiUserspaceFreeMM) = %d, want %d", got, want)
	}
	if got, want := unsafe.Sizeof(linux.HemiUserspaceMapFile{}), uintptr(96); got != want {
		t.Fatalf("sizeof(HemiUserspaceMapFile) = %d, want %d", got, want)
	}
	filePage := linux.HemiUserspaceFilePage{}
	if got, want := unsafe.Sizeof(filePage), uintptr(16); got != want {
		t.Fatalf("sizeof(HemiUserspaceFilePage) = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(filePage.HostOffset), uintptr(8); got != want {
		t.Fatalf("offsetof(HemiUserspaceFilePage.HostOffset) = %d, want %d", got, want)
	}
	fileFault := linux.HemiUserspaceFileFault{}
	if got, want := unsafe.Sizeof(fileFault), uintptr(320); got != want {
		t.Fatalf("sizeof(HemiUserspaceFileFault) = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(fileFault.PageSource), uintptr(52); got != want {
		t.Fatalf("offsetof(HemiUserspaceFileFault.PageSource) = %d, want %d", got, want)
	}
	releaseRing := linux.HemiUserspaceReleaseRing{}
	if got, want := unsafe.Sizeof(releaseRing), uintptr(1664); got != want {
		t.Fatalf("sizeof(HemiUserspaceReleaseRing) = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(releaseRing.Tail), uintptr(64); got != want {
		t.Fatalf("offsetof(HemiUserspaceReleaseRing.Tail) = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(releaseRing.Records), uintptr(128); got != want {
		t.Fatalf("offsetof(HemiUserspaceReleaseRing.Records) = %d, want %d", got, want)
	}
	if got, want := unsafe.Sizeof(linux.HemiUserspaceReleaseSetup{}), uintptr(24); got != want {
		t.Fatalf("sizeof(HemiUserspaceReleaseSetup) = %d, want %d", got, want)
	}
}

func TestHemiGvisorRingTransferThreshold(t *testing.T) {
	for _, test := range []struct {
		length int
		want   bool
	}{
		{length: 0, want: false},
		{length: 4, want: false},
		{length: hemiGvisorRingMinBytes - 1, want: false},
		{length: hemiGvisorRingMinBytes, want: true},
		{length: hemiGvisorRingSlotBytes, want: true},
	} {
		if got := hemiGvisorUseRing(test.length); got != test.want {
			t.Errorf("hemiGvisorUseRing(%d) = %t, want %t", test.length, got, test.want)
		}
	}
}

func newTestHemiGvisorRingLane() *hemiGvisorRingLane {
	mapping := make([]byte, hemiGvisorRingMapSize)
	return &hemiGvisorRingLane{ringID: 17, mapping: mapping}
}

func newTestHemiGvisorRingPool(lanes ...*hemiGvisorRingLane) *hemiGvisorRingPool {
	return newHemiGvisorRingPool(lanes)
}

func TestHemiGvisorRingPoolLeasesLanesIndependently(t *testing.T) {
	lanes := make([]*hemiGvisorRingLane, 4)
	for i := range lanes {
		lanes[i] = newTestHemiGvisorRingLane()
	}
	pool := newHemiGvisorRingPool(lanes)
	leased := make(map[*hemiGvisorRingLane]struct{}, len(lanes))
	for range lanes {
		lane := pool.tryAcquire(7, hostarch.Addr(linux.HEMI_USERSPACE_VMAR_START))
		if lane == nil {
			t.Fatal("ring pool ran out before every lane was leased")
		}
		if _, ok := leased[lane]; ok {
			t.Fatalf("ring lane %p was leased twice", lane)
		}
		leased[lane] = struct{}{}
	}
	if lane := pool.tryAcquire(7, hostarch.Addr(linux.HEMI_USERSPACE_VMAR_START)); lane != nil {
		t.Fatalf("fully leased ring pool returned lane %p", lane)
	}
	for lane := range leased {
		pool.release(lane)
	}
}

func TestHemiGvisorRingReadBatches(t *testing.T) {
	lane := newTestHemiGvisorRingLane()
	const (
		deviceFD = int32(7)
		mmid     = uint64(23)
		base     = hostarch.Addr(linux.HEMI_USERSPACE_VMAR_START)
	)
	dst := make([]byte, hemiGvisorRingBatchBytes+123)
	enterCalls := 0
	totalDescriptors := 0
	n, err := lane.transfer(deviceFD, mmid, base, dst, linux.HEMI_USERSPACE_RING_OP_READ,
		func(gotFD int32, enter *linux.HemiUserspaceRingEnter) unix.Errno {
			enterCalls++
			if gotFD != deviceFD || enter.RingID != lane.ringID || enter.MMID != mmid || enter.Reserved != 0 {
				t.Errorf("ENTER = (fd:%d, %+v), want fd:%d ring:%d mmid:%d", gotFD, *enter, deviceFD, lane.ringID, mmid)
			}
			if enter.Count == 0 || enter.Count > hemiGvisorRingEntries {
				t.Fatalf("ENTER count = %d, want 1..%d", enter.Count, hemiGvisorRingEntries)
			}
			for i := 0; i < int(enter.Count); i++ {
				descriptor := lane.descriptor(i)
				if descriptor.Op != linux.HEMI_USERSPACE_RING_OP_READ || descriptor.Flags != 0 {
					t.Errorf("descriptor %d = %+v, want READ with zero flags", i, *descriptor)
				}
				value := byte(totalDescriptors + i + 1)
				for j := range lane.data(i, int(descriptor.Len)) {
					lane.data(i, int(descriptor.Len))[j] = value
				}
				descriptor.Done = descriptor.Len
				descriptor.Result = 0
			}
			totalDescriptors += int(enter.Count)
			return 0
		})
	if err != nil || n != len(dst) {
		t.Fatalf("ring read = (%d, %v), want (%d, nil)", n, err, len(dst))
	}
	if enterCalls != 2 || totalDescriptors != 9 {
		t.Fatalf("ring read used %d ENTERs/%d descriptors, want 2/9", enterCalls, totalDescriptors)
	}
	for i := 0; i < 9; i++ {
		offset := i * hemiGvisorRingSlotBytes
		if got, want := dst[offset], byte(i+1); got != want {
			t.Errorf("dst[%d] = %d, want %d", offset, got, want)
		}
	}
}

func TestHemiGvisorRingWriteAndPartialRead(t *testing.T) {
	const base = hostarch.Addr(linux.HEMI_USERSPACE_VMAR_START)

	t.Run("write", func(t *testing.T) {
		lane := newTestHemiGvisorRingLane()
		src := make([]byte, hemiGvisorRingBatchBytes+2*hemiGvisorRingSlotBytes+17)
		for i := range src {
			src[i] = byte(i)
		}
		enterCalls := 0
		offset := 0
		n, err := lane.transfer(3, 5, base, src, linux.HEMI_USERSPACE_RING_OP_WRITE,
			func(_ int32, enter *linux.HemiUserspaceRingEnter) unix.Errno {
				enterCalls++
				for i := 0; i < int(enter.Count); i++ {
					descriptor := lane.descriptor(i)
					length := int(descriptor.Len)
					if descriptor.Addr != uint64(base+hostarch.Addr(offset)) ||
						descriptor.Op != linux.HEMI_USERSPACE_RING_OP_WRITE ||
						!bytes.Equal(lane.data(i, length), src[offset:offset+length]) {
						t.Errorf("descriptor %d did not contain the expected WRITE payload", i)
					}
					descriptor.Done = descriptor.Len
					descriptor.Result = 0
					offset += length
				}
				return 0
			})
		if err != nil || n != len(src) {
			t.Fatalf("ring write = (%d, %v), want (%d, nil)", n, err, len(src))
		}
		if enterCalls != 2 || offset != len(src) {
			t.Fatalf("ring write used %d ENTERs and consumed %d bytes, want 2 and %d", enterCalls, offset, len(src))
		}
	})

	t.Run("partial read", func(t *testing.T) {
		lane := newTestHemiGvisorRingLane()
		dst := bytes.Repeat([]byte{0xcc}, 3*hemiGvisorRingSlotBytes)
		const partial = 37
		n, err := lane.transfer(3, 5, base, dst, linux.HEMI_USERSPACE_RING_OP_READ,
			func(_ int32, enter *linux.HemiUserspaceRingEnter) unix.Errno {
				if enter.Count != 3 {
					t.Fatalf("ENTER count = %d, want 3", enter.Count)
				}
				for i := range lane.data(0, hemiGvisorRingSlotBytes) {
					lane.data(0, hemiGvisorRingSlotBytes)[i] = 0x11
				}
				lane.descriptor(0).Done = lane.descriptor(0).Len
				for i := range lane.data(1, partial) {
					lane.data(1, partial)[i] = 0x22
				}
				lane.descriptor(1).Done = partial
				lane.descriptor(1).Result = -int32(unix.EFAULT)
				lane.descriptor(2).Done = 0
				lane.descriptor(2).Result = -int32(unix.ECANCELED)
				return 0
			})
		if want := hemiGvisorRingSlotBytes + partial; n != want {
			t.Fatalf("partial ring read progress = %d, want %d", n, want)
		}
		fault, ok := err.(platform.SegmentationFault)
		if !ok {
			t.Fatalf("partial ring read error = %T(%v), want platform.SegmentationFault", err, err)
		}
		if want := base + hostarch.Addr(n); fault.Addr != want {
			t.Fatalf("partial ring fault address = %#x, want %#x", fault.Addr, want)
		}
		if dst[0] != 0x11 || dst[hemiGvisorRingSlotBytes] != 0x22 || dst[n] != 0xcc {
			t.Fatalf("partial ring read copied bytes outside its completed prefix")
		}
	})

	t.Run("partial write", func(t *testing.T) {
		lane := newTestHemiGvisorRingLane()
		src := make([]byte, 3*hemiGvisorRingSlotBytes)
		const partial = 37
		n, err := lane.transfer(3, 5, base, src, linux.HEMI_USERSPACE_RING_OP_WRITE,
			func(_ int32, enter *linux.HemiUserspaceRingEnter) unix.Errno {
				if enter.Count != 3 {
					t.Fatalf("ENTER count = %d, want 3", enter.Count)
				}
				lane.descriptor(0).Done = lane.descriptor(0).Len
				lane.descriptor(1).Done = partial
				lane.descriptor(1).Result = -int32(unix.EFAULT)
				lane.descriptor(2).Result = -int32(unix.ECANCELED)
				return 0
			})
		if want := hemiGvisorRingSlotBytes + partial; n != want {
			t.Fatalf("partial ring write progress = %d, want %d", n, want)
		}
		fault, ok := err.(platform.SegmentationFault)
		if !ok {
			t.Fatalf("partial ring write error = %T(%v), want platform.SegmentationFault", err, err)
		}
		if want := base + hostarch.Addr(n); fault.Addr != want {
			t.Fatalf("partial ring write fault address = %#x, want %#x", fault.Addr, want)
		}
	})
}

func TestHemiGvisorRingEnterErrorIsReturned(t *testing.T) {
	for _, test := range []struct {
		name         string
		length       int
		failCall     int
		wantProgress int
	}{
		{name: "first batch", length: 16, failCall: 1},
		{name: "second batch", length: hemiGvisorRingBatchBytes + 16, failCall: 2, wantProgress: hemiGvisorRingBatchBytes},
	} {
		t.Run(test.name, func(t *testing.T) {
			lane := newTestHemiGvisorRingLane()
			called := 0
			n, err := lane.transfer(3, 5, hostarch.Addr(linux.HEMI_USERSPACE_VMAR_START), make([]byte, test.length), linux.HEMI_USERSPACE_RING_OP_READ,
				func(_ int32, enter *linux.HemiUserspaceRingEnter) unix.Errno {
					called++
					if called == test.failCall {
						return unix.EIO
					}
					for i := 0; i < int(enter.Count); i++ {
						lane.descriptor(i).Done = lane.descriptor(i).Len
					}
					return 0
				})
			var enterErr *hemiGvisorRingEnterError
			if n != test.wantProgress || !errors.Is(err, unix.EIO) || !errors.As(err, &enterErr) || called != test.failCall {
				t.Fatalf("ring ENTER error = (%d, %T(%v), calls:%d), want (%d, *hemiGvisorRingEnterError(EIO), %d)", n, err, err, called, test.wantProgress, test.failCall)
			}
		})
	}
}

func TestHemiGvisorAddressSpaceIOIterUsesRingBuffer(t *testing.T) {
	lane := newTestHemiGvisorRingLane()
	ringPool := newTestHemiGvisorRingPool(lane)
	const (
		deviceFD = int32(3)
		mmid     = uint64(5)
		base     = hostarch.Addr(linux.HEMI_USERSPACE_VMAR_START)
	)
	length := hemiGvisorRingBatchBytes + 123
	source := make([]byte, length)
	for i := range source {
		source[i] = byte(i)
	}

	var ringWrite []byte
	device := &hemiGvisorDeviceState{fd: deviceFD, ringPool: ringPool}
	enterFn := func(gotFD int32, enter *linux.HemiUserspaceRingEnter) unix.Errno {
		if gotFD != deviceFD || enter.MMID != mmid {
			t.Fatalf("ENTER = (fd:%d, mmid:%d), want (%d, %d)", gotFD, enter.MMID, deviceFD, mmid)
		}
		for i := 0; i < int(enter.Count); i++ {
			desc := lane.descriptor(i)
			switch desc.Op {
			case linux.HEMI_USERSPACE_RING_OP_WRITE:
				ringWrite = append(ringWrite, lane.data(i, int(desc.Len))...)
			case linux.HEMI_USERSPACE_RING_OP_READ:
				offset := int(hostarch.Addr(desc.Addr) - base)
				copy(lane.data(i, int(desc.Len)), source[offset:offset+int(desc.Len)])
			default:
				t.Fatalf("descriptor %d has unexpected op %d", i, desc.Op)
			}
			desc.Done = desc.Len
			desc.Result = 0
		}
		return 0
	}
	s := subprocess{
		hemiGvisorDevice: device,
		hemiGvisorTGID:   1,
		hemiGvisorMMID:   mmid,
	}
	ars := hostarch.AddrRangeSeqOf(hostarch.AddrRange{Start: base, End: base + hostarch.Addr(length)})

	readerState := safemem.BlockSeqReader{Blocks: safemem.BlockSeqOf(safemem.BlockFromSafeSlice(source))}
	readerCalls := 0
	reader := safemem.ReaderFunc(func(dsts safemem.BlockSeq) (uint64, error) {
		readerCalls++
		block := dsts.Head().ToSlice()
		if len(block) == 0 || &block[0] != &lane.mapping[hemiGvisorRingDataOffset] {
			t.Fatal("Reader did not receive the ring lane data buffer directly")
		}
		return readerState.ReadToBlocks(dsts)
	})
	if n, err := s.copyOutFromIter(ars, reader, nil, enterFn); n != int64(length) || err != nil {
		t.Fatalf("CopyOutFromIter = (%d, %v), want (%d, nil)", n, err, length)
	}
	if readerCalls != 2 || !bytes.Equal(ringWrite, source) {
		t.Fatalf("direct ring write used %d Reader calls and copied %d bytes, want 2 and %d", readerCalls, len(ringWrite), length)
	}

	var got bytes.Buffer
	writerCalls := 0
	writer := safemem.WriterFunc(func(srcs safemem.BlockSeq) (uint64, error) {
		writerCalls++
		block := srcs.Head().ToSlice()
		if len(block) == 0 || &block[0] != &lane.mapping[hemiGvisorRingDataOffset] {
			t.Fatal("Writer did not receive the ring lane data buffer directly")
		}
		return safemem.FromIOWriter{Writer: &got}.WriteFromBlocks(srcs)
	})
	if n, err := s.copyInToIter(ars, writer, nil, enterFn); n != int64(length) || err != nil {
		t.Fatalf("CopyInToIter = (%d, %v), want (%d, nil)", n, err, length)
	}
	if writerCalls != 2 || !bytes.Equal(got.Bytes(), source) {
		t.Fatalf("direct ring read used %d Writer calls and copied %d bytes, want 2 and %d", writerCalls, got.Len(), length)
	}
}

func TestHemiGvisorHotAliasLazyAdmission(t *testing.T) {
	const addr = hostarch.Addr(linux.HEMI_USERSPACE_VMAR_START)
	var s subprocess

	for i := 1; i < hemiGvisorHotAliasWarmup; i++ {
		if ok, err := s.hemiGvisorPrepareHotAlias(addr, 1, 0); ok || err != nil {
			t.Fatalf("attempt %d = (%t, %v), want (false, nil)", i, ok, err)
		}
		if cache := s.hemiGvisorHotAlias.Load(); cache != nil {
			t.Fatalf("attempt %d allocated cache before warmup", i)
		}
	}
	if ok, err := s.hemiGvisorPrepareHotAlias(addr, 1, 0); ok || err != nil {
		t.Fatalf("warmup attempt = (%t, %v), want (false, nil)", ok, err)
	}
	if cache := s.hemiGvisorHotAlias.Load(); cache == nil {
		t.Fatal("warmup attempt did not allocate cache")
	}
}

func TestHemiGvisorHotAliasAdmissionRequiresStablePage(t *testing.T) {
	s := &subprocess{}
	base := hostarch.Addr(linux.HEMI_USERSPACE_VMAR_START)
	for i := 0; i < 2*hemiGvisorHotAliasWarmup; i++ {
		addr := base + hostarch.Addr(i&1)*hostarch.PageSize
		if ok, err := s.hemiGvisorPrepareHotAlias(addr, 1, 0); ok || err != nil {
			t.Fatalf("prepare(%#x) = (%t, %v), want (false, nil)", addr, ok, err)
		}
	}
	if cache := s.hemiGvisorHotAlias.Load(); cache != nil {
		t.Fatalf("alternating pages allocated cache: %+v", cache)
	}
}

func TestHemiGvisorHotAliasIterDoesNotExposeAliasToStream(t *testing.T) {
	const base = hostarch.Addr(linux.HEMI_USERSPACE_VMAR_START)
	source := bytes.Repeat([]byte{0x5a}, 512)
	cache := &hemiGvisorHotAliasCache{
		mapping: make([]byte, hemiGvisorHotAliasSlots*hostarch.PageSize),
	}
	slot := hemiGvisorHotAliasSlot(base)
	cache.keys[slot].Store(hemiGvisorHotAliasKey(
		base, linux.HEMI_USERSPACE_ACCESS_WRITE))
	s := subprocess{}
	s.hemiGvisorHotAlias.Store(cache)
	ars := hostarch.AddrRangeSeqOf(hostarch.AddrRange{
		Start: base,
		End:   base + hostarch.Addr(len(source)),
	})

	readerCalls := 0
	reader := safemem.ReaderFunc(func(dsts safemem.BlockSeq) (uint64, error) {
		readerCalls++
		if dsts.Head().NeedSafecopy() {
			return 0, unix.EFAULT
		}
		return safemem.CopySeq(dsts, safemem.BlockSeqOf(
			safemem.BlockFromSafeSlice(source)))
	})
	n, err, ok := s.hemiGvisorTryHotAliasCopyOutFromIter(ars, reader, nil)
	if !ok || err != nil || n != int64(len(source)) || readerCalls != 1 {
		t.Fatalf("hot-alias CopyOutFromIter = (%d, %v, %t, calls:%d), want (%d, nil, true, calls:1)", n, err, ok, readerCalls, len(source))
	}
	offset := int(slot) * hostarch.PageSize
	if got := cache.mapping[offset : offset+len(source)]; !bytes.Equal(got, source) {
		t.Fatal("hot-alias CopyOutFromIter copied incorrect data")
	}

	var got bytes.Buffer
	writerCalls := 0
	writer := safemem.WriterFunc(func(srcs safemem.BlockSeq) (uint64, error) {
		writerCalls++
		if srcs.Head().NeedSafecopy() {
			return 0, unix.EFAULT
		}
		return safemem.FromIOWriter{Writer: &got}.WriteFromBlocks(srcs)
	})
	n, err, ok = s.hemiGvisorTryHotAliasCopyInToIter(ars, writer, nil)
	if !ok || err != nil || n != int64(len(source)) || writerCalls != 1 {
		t.Fatalf("hot-alias CopyInToIter = (%d, %v, %t, calls:%d), want (%d, nil, true, calls:1)", n, err, ok, writerCalls, len(source))
	}
	if !bytes.Equal(got.Bytes(), source) {
		t.Fatal("hot-alias CopyInToIter copied incorrect data")
	}
}

func TestHemiGvisorAddressSpaceIOIterWaitsForRingLane(t *testing.T) {
	lane := newTestHemiGvisorRingLane()
	ringPool := newTestHemiGvisorRingPool(lane)
	held := ringPool.acquire(5, hostarch.Addr(linux.HEMI_USERSPACE_VMAR_START))
	device := &hemiGvisorDeviceState{ringPool: ringPool}
	s := subprocess{
		hemiGvisorDevice: device,
		hemiGvisorTGID:   1,
		hemiGvisorMMID:   5,
	}
	ars := hostarch.AddrRangeSeqOf(hostarch.AddrRange{
		Start: hostarch.Addr(linux.HEMI_USERSPACE_VMAR_START),
		End:   hostarch.Addr(linux.HEMI_USERSPACE_VMAR_START + 1),
	})
	type result struct {
		n   int64
		err error
	}
	resultCh := make(chan result, 1)
	go func() {
		n, err := s.copyOutFromIter(ars, safemem.ReaderFunc(func(dsts safemem.BlockSeq) (uint64, error) {
			return safemem.ZeroSeq(dsts)
		}), nil, func(_ int32, enter *linux.HemiUserspaceRingEnter) unix.Errno {
			for i := 0; i < int(enter.Count); i++ {
				lane.descriptor(i).Done = lane.descriptor(i).Len
			}
			return 0
		})
		resultCh <- result{n: n, err: err}
	}()

	deadline := time.Now().Add(time.Second)
	for ringPool.waiters.Load() == 0 && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if ringPool.waiters.Load() == 0 {
		t.Fatal("stream did not wait for the busy ring lane")
	}
	select {
	case got := <-resultCh:
		t.Fatalf("stream returned before a ring lane was available: (%d, %v)", got.n, got.err)
	default:
	}
	ringPool.release(held)
	got := <-resultCh
	if got.n != 1 || got.err != nil {
		t.Fatalf("stream after ring lane release = (%d, %v), want (1, nil)", got.n, got.err)
	}
}

func TestHemiGvisorAddressSpaceIOIterRetriesFileFaultWithoutRereading(t *testing.T) {
	lane := newTestHemiGvisorRingLane()
	ringPool := newTestHemiGvisorRingPool(lane)
	const (
		deviceFD = int32(3)
		mmid     = uint64(5)
		base     = hostarch.Addr(linux.HEMI_USERSPACE_VMAR_START)
	)
	device := &hemiGvisorDeviceState{fd: deviceFD, ringPool: ringPool}
	s := subprocess{
		hemiGvisorDevice: device,
		hemiGvisorTGID:   1,
		hemiGvisorMMID:   mmid,
	}
	source := bytes.Repeat([]byte{0x5a}, hostarch.PageSize)
	ars := hostarch.AddrRangeSeqOf(hostarch.AddrRange{Start: base, End: base + hostarch.Addr(len(source))})

	readerCalls := 0
	reader := safemem.ReaderFunc(func(dsts safemem.BlockSeq) (uint64, error) {
		readerCalls++
		return safemem.CopySeq(dsts, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(source)))
	})
	enterCalls := 0
	enterFn := func(int32, *linux.HemiUserspaceRingEnter) unix.Errno {
		enterCalls++
		desc := lane.descriptor(0)
		if enterCalls == 1 {
			desc.Result = -int32(unix.EAGAIN)
			return 0
		}
		if got := lane.data(0, int(desc.Len)); !bytes.Equal(got, source) {
			t.Fatal("ring retry did not retain the Reader's data")
		}
		desc.Done = desc.Len
		desc.Result = 0
		return 0
	}
	faultCalls := 0
	handleFault := func(addr hostarch.Addr, at hostarch.AccessType) error {
		faultCalls++
		if addr != base || at != hostarch.Write {
			t.Fatalf("fault handler = (%#x, %v), want (%#x, %v)", addr, at, base, hostarch.Write)
		}
		return nil
	}

	if n, err := s.copyOutFromIter(ars, reader, handleFault, enterFn); n != int64(len(source)) || err != nil {
		t.Fatalf("CopyOutFromIter = (%d, %v), want (%d, nil)", n, err, len(source))
	}
	if readerCalls != 1 || enterCalls != 2 || faultCalls != 1 {
		t.Fatalf("retry calls = (reader:%d, enter:%d, fault:%d), want (1, 2, 1)", readerCalls, enterCalls, faultCalls)
	}
}

func TestHemiGvisorAddressSpaceIOIterRetriesInitialReadFileFault(t *testing.T) {
	lane := newTestHemiGvisorRingLane()
	ringPool := newTestHemiGvisorRingPool(lane)
	const (
		deviceFD = int32(3)
		mmid     = uint64(5)
		base     = hostarch.Addr(linux.HEMI_USERSPACE_VMAR_START)
	)
	device := &hemiGvisorDeviceState{fd: deviceFD, ringPool: ringPool}
	s := subprocess{
		hemiGvisorDevice: device,
		hemiGvisorTGID:   1,
		hemiGvisorMMID:   mmid,
	}
	source := bytes.Repeat([]byte{0x5a}, hostarch.PageSize)
	copy(lane.data(0, len(source)), source)
	ars := hostarch.AddrRangeSeqOf(hostarch.AddrRange{Start: base, End: base + hostarch.Addr(len(source))})

	enterCalls := 0
	enterFn := func(int32, *linux.HemiUserspaceRingEnter) unix.Errno {
		enterCalls++
		desc := lane.descriptor(0)
		if enterCalls == 1 {
			desc.Result = -int32(unix.EAGAIN)
			return 0
		}
		desc.Done = desc.Len
		desc.Result = 0
		return 0
	}
	faultCalls := 0
	handleFault := func(addr hostarch.Addr, at hostarch.AccessType) error {
		faultCalls++
		if addr != base || at != hostarch.Read {
			t.Fatalf("fault handler = (%#x, %v), want (%#x, %v)", addr, at, base, hostarch.Read)
		}
		return nil
	}
	var got bytes.Buffer

	if n, err := s.copyInToIter(
		ars, safemem.FromIOWriter{Writer: &got}, handleFault, enterFn,
	); n != int64(len(source)) || err != nil {
		t.Fatalf("CopyInToIter = (%d, %v), want (%d, nil)", n, err, len(source))
	}
	if enterCalls != 2 || faultCalls != 1 || !bytes.Equal(got.Bytes(), source) {
		t.Fatalf("retry result = (enter:%d, fault:%d, data:%t), want (2, 1, true)",
			enterCalls, faultCalls, bytes.Equal(got.Bytes(), source))
	}
}
