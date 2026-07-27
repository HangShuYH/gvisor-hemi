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
	"io"
	"math"
	"sync/atomic"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

type hemiGvisorTestMapping struct {
	refs int
	data [hostarch.PageSize]byte
}

func (i *hemiGvisorTestMapping) IncRef() {
	i.refs++
}

func (i *hemiGvisorTestMapping) DecRef(context.Context) {
	i.refs--
}

func (i *hemiGvisorTestMapping) ReadAt(_ context.Context, dst []byte, off uint64) (int, error) {
	if off >= uint64(len(i.data)) {
		return 0, io.EOF
	}
	n := copy(dst, i.data[off:])
	if n != len(dst) {
		return n, io.EOF
	}
	return n, nil
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
	if err := device.releaseToken(ctx, inodeToken, linux.HEMI_USERSPACE_RELEASE_INODE, 1); err != nil {
		t.Fatalf("release inode token: %v", err)
	}
	if got := provider.refs; got != 0 {
		t.Fatalf("provider refs after inode release = %d, want 0", got)
	}
	if got := len(device.tokens); got != 0 {
		t.Fatalf("registry length after release = %d, want 0", got)
	}
	if err := device.releaseToken(ctx, fileToken, linux.HEMI_USERSPACE_RELEASE_FILE, 1); err == nil {
		t.Fatal("duplicate file release unexpectedly succeeded")
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

func TestHemiGvisorPageTokenOwnership(t *testing.T) {
	ctx := context.Background()
	provider := &hemiGvisorTestMapping{}
	for i := range provider.data {
		provider.data[i] = byte(i)
	}
	device := &hemiGvisorDeviceState{tokens: make(map[uint64]hemiGvisorToken)}

	page, err := device.prepareFilePage(ctx, provider, 0)
	if err != nil {
		t.Fatalf("prepareFilePage: %v", err)
	}
	if page.PageToken == 0 || page.PageVA%uint64(hostarch.PageSize) != 0 {
		t.Fatalf("prepareFilePage returned invalid token/VA: %+v", page)
	}
	pageData := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(page.PageVA))), hostarch.PageSize)
	if !bytes.Equal(pageData, provider.data[:]) {
		t.Fatal("prepareFilePage returned incorrect file contents")
	}
	if len(device.tokens) != 1 {
		t.Fatalf("page tokens after prepare = %d, want 1", len(device.tokens))
	}
	if err := device.releaseToken(ctx, page.PageToken, linux.HEMI_USERSPACE_RELEASE_PAGE, 1); err != nil {
		t.Fatalf("release page token: %v", err)
	}
	if len(device.tokens) != 0 {
		t.Fatalf("page tokens after release = %d, want 0", len(device.tokens))
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
	lanes := make(chan *hemiGvisorRingLane, 1)
	lanes <- lane
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
	device := &hemiGvisorDeviceState{fd: deviceFD, lanes: lanes}
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

func TestHemiGvisorAddressSpaceIOIterUnavailableDoesNotConsumeStream(t *testing.T) {
	device := &hemiGvisorDeviceState{lanes: make(chan *hemiGvisorRingLane)}
	s := subprocess{
		hemiGvisorDevice: device,
		hemiGvisorTGID:   1,
		hemiGvisorMMID:   5,
	}
	ars := hostarch.AddrRangeSeqOf(hostarch.AddrRange{
		Start: hostarch.Addr(linux.HEMI_USERSPACE_VMAR_START),
		End:   hostarch.Addr(linux.HEMI_USERSPACE_VMAR_START + 1),
	})
	readerCalls := 0
	_, err := s.CopyOutFromIter(ars, safemem.ReaderFunc(func(dsts safemem.BlockSeq) (uint64, error) {
		readerCalls++
		return 0, nil
	}), nil)
	if _, ok := err.(platform.AddressSpaceIOUnavailable); !ok || readerCalls != 0 {
		t.Fatalf("unavailable stream = (%T(%v), Reader calls:%d), want (AddressSpaceIOUnavailable, 0)", err, err, readerCalls)
	}
}

func TestHemiGvisorAddressSpaceIOIterRetriesFileFaultWithoutRereading(t *testing.T) {
	lane := newTestHemiGvisorRingLane()
	lanes := make(chan *hemiGvisorRingLane, 1)
	lanes <- lane
	const (
		deviceFD = int32(3)
		mmid     = uint64(5)
		base     = hostarch.Addr(linux.HEMI_USERSPACE_VMAR_START)
	)
	device := &hemiGvisorDeviceState{fd: deviceFD, lanes: lanes}
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
	lanes := make(chan *hemiGvisorRingLane, 1)
	lanes <- lane
	const (
		deviceFD = int32(3)
		mmid     = uint64(5)
		base     = hostarch.Addr(linux.HEMI_USERSPACE_VMAR_START)
	)
	device := &hemiGvisorDeviceState{fd: deviceFD, lanes: lanes}
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
