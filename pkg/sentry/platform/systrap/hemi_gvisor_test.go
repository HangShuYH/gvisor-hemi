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
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

func TestHemiGvisorContainsUserMem(t *testing.T) {
	tests := []struct {
		name   string
		addr   uint64
		length uint64
		want   bool
	}{
		{name: "empty below range", addr: 0, length: 0, want: true},
		{name: "first byte", addr: linux.HEMI_GVISOR_VMAR_START, length: 1, want: true},
		{name: "last byte", addr: linux.HEMI_GVISOR_VMAR_END - 1, length: 1, want: true},
		{name: "entire range", addr: linux.HEMI_GVISOR_VMAR_START, length: linux.HEMI_GVISOR_VMAR_END - linux.HEMI_GVISOR_VMAR_START, want: true},
		{name: "below range", addr: linux.HEMI_GVISOR_VMAR_START - 1, length: 1, want: false},
		{name: "crosses start", addr: linux.HEMI_GVISOR_VMAR_START - 1, length: 2, want: false},
		{name: "at end", addr: linux.HEMI_GVISOR_VMAR_END, length: 1, want: false},
		{name: "crosses end", addr: linux.HEMI_GVISOR_VMAR_END - 1, length: 2, want: false},
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

func TestHemiGvisorKeepSyscallUnpatched(t *testing.T) {
	inactive := subprocess{}
	active := subprocess{hemiGvisorTGID: 1, hemiGvisorMMHandle: 1}
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
	const addr = hostarch.Addr(linux.HEMI_GVISOR_VMAR_START)

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
	setup := linux.HemiGvisorRingSetup{}
	if got, want := unsafe.Sizeof(setup), uintptr(64); got != want {
		t.Fatalf("sizeof(HemiGvisorRingSetup) = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(setup.Features), uintptr(8); got != want {
		t.Fatalf("offsetof(HemiGvisorRingSetup.Features) = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(setup.RingID), uintptr(16); got != want {
		t.Fatalf("offsetof(HemiGvisorRingSetup.RingID) = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(setup.MmapSize), uintptr(32); got != want {
		t.Fatalf("offsetof(HemiGvisorRingSetup.MmapSize) = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(setup.MaxBytes), uintptr(60); got != want {
		t.Fatalf("offsetof(HemiGvisorRingSetup.MaxBytes) = %d, want %d", got, want)
	}

	header := linux.HemiGvisorRingHeader{}
	if got, want := unsafe.Sizeof(header), uintptr(64); got != want {
		t.Fatalf("sizeof(HemiGvisorRingHeader) = %d, want %d", got, want)
	}
	for name, got := range map[string]uintptr{
		"Magic":            unsafe.Offsetof(header.Magic),
		"ABIVersion":       unsafe.Offsetof(header.ABIVersion),
		"HeaderSize":       unsafe.Offsetof(header.HeaderSize),
		"RingID":           unsafe.Offsetof(header.RingID),
		"Entries":          unsafe.Offsetof(header.Entries),
		"DescriptorOffset": unsafe.Offsetof(header.DescriptorOffset),
		"DescriptorSize":   unsafe.Offsetof(header.DescriptorSize),
		"DataOffset":       unsafe.Offsetof(header.DataOffset),
		"DataStride":       unsafe.Offsetof(header.DataStride),
		"MaxBytes":         unsafe.Offsetof(header.MaxBytes),
		"Features":         unsafe.Offsetof(header.Features),
		"Reserved":         unsafe.Offsetof(header.Reserved),
	} {
		want := map[string]uintptr{
			"Magic": 0, "ABIVersion": 8, "HeaderSize": 12, "RingID": 16,
			"Entries": 24, "DescriptorOffset": 28, "DescriptorSize": 32,
			"DataOffset": 36, "DataStride": 40, "MaxBytes": 44,
			"Features": 48, "Reserved": 56,
		}[name]
		if got != want {
			t.Errorf("offsetof(HemiGvisorRingHeader.%s) = %d, want %d", name, got, want)
		}
	}

	descriptor := linux.HemiGvisorRingDescriptor{}
	if got, want := unsafe.Sizeof(descriptor), uintptr(64); got != want {
		t.Fatalf("sizeof(HemiGvisorRingDescriptor) = %d, want %d", got, want)
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
			t.Errorf("offsetof(HemiGvisorRingDescriptor.%s) = %d, want %d", name, got, want)
		}
	}

	enter := linux.HemiGvisorRingEnter{}
	if got, want := unsafe.Sizeof(enter), uintptr(32); got != want {
		t.Fatalf("sizeof(HemiGvisorRingEnter) = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(enter.Reserved), uintptr(24); got != want {
		t.Fatalf("offsetof(HemiGvisorRingEnter.Reserved) = %d, want %d", got, want)
	}
}

func newTestHemiGvisorRingLane() *hemiGvisorRingLane {
	mapping := make([]byte, hemiGvisorRingMapSize)
	header := (*linux.HemiGvisorRingHeader)(unsafe.Pointer(&mapping[0]))
	*header = linux.HemiGvisorRingHeader{
		Magic:            linux.HEMI_GVISOR_RING_MAGIC,
		ABIVersion:       linux.HEMI_GVISOR_RING_ABI,
		HeaderSize:       hemiGvisorRingHeaderSize,
		RingID:           17,
		Entries:          hemiGvisorRingEntries,
		DescriptorOffset: hemiGvisorRingDescriptorOffset,
		DescriptorSize:   hemiGvisorRingDescriptorSize,
		DataOffset:       hemiGvisorRingDataOffset,
		DataStride:       hemiGvisorRingDataStride,
		MaxBytes:         hemiGvisorRingBatchBytes,
	}
	return &hemiGvisorRingLane{ringID: 17, mapping: mapping}
}

func TestHemiGvisorRingReadBatches(t *testing.T) {
	lane := newTestHemiGvisorRingLane()
	const (
		deviceFD = int32(7)
		mmHandle = uint64(23)
		base     = hostarch.Addr(linux.HEMI_GVISOR_VMAR_START)
	)
	dst := make([]byte, hemiGvisorRingBatchBytes+123)
	enterCalls := 0
	totalDescriptors := 0
	n, err := lane.transfer(deviceFD, mmHandle, base, dst, linux.HEMI_GVISOR_RING_OP_READ,
		func(gotFD int32, enter *linux.HemiGvisorRingEnter) unix.Errno {
			enterCalls++
			if gotFD != deviceFD || enter.RingID != lane.ringID || enter.MMHandle != mmHandle || enter.Flags != 0 || enter.Reserved != 0 {
				t.Errorf("ENTER = (fd:%d, %+v), want fd:%d ring:%d handle:%d", gotFD, *enter, deviceFD, lane.ringID, mmHandle)
			}
			if enter.Count == 0 || enter.Count > hemiGvisorRingEntries {
				t.Fatalf("ENTER count = %d, want 1..%d", enter.Count, hemiGvisorRingEntries)
			}
			for i := 0; i < int(enter.Count); i++ {
				descriptor := lane.descriptor(i)
				if descriptor.Op != linux.HEMI_GVISOR_RING_OP_READ || descriptor.Flags != 0 {
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
	const base = hostarch.Addr(linux.HEMI_GVISOR_VMAR_START)

	t.Run("write", func(t *testing.T) {
		lane := newTestHemiGvisorRingLane()
		src := make([]byte, hemiGvisorRingBatchBytes+2*hemiGvisorRingSlotBytes+17)
		for i := range src {
			src[i] = byte(i)
		}
		enterCalls := 0
		offset := 0
		n, err := lane.transfer(3, 5, base, src, linux.HEMI_GVISOR_RING_OP_WRITE,
			func(_ int32, enter *linux.HemiGvisorRingEnter) unix.Errno {
				enterCalls++
				for i := 0; i < int(enter.Count); i++ {
					descriptor := lane.descriptor(i)
					length := int(descriptor.Len)
					if descriptor.Addr != uint64(base+hostarch.Addr(offset)) ||
						descriptor.Op != linux.HEMI_GVISOR_RING_OP_WRITE ||
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
		n, err := lane.transfer(3, 5, base, dst, linux.HEMI_GVISOR_RING_OP_READ,
			func(_ int32, enter *linux.HemiGvisorRingEnter) unix.Errno {
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
		n, err := lane.transfer(3, 5, base, src, linux.HEMI_GVISOR_RING_OP_WRITE,
			func(_ int32, enter *linux.HemiGvisorRingEnter) unix.Errno {
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
			n, err := lane.transfer(3, 5, hostarch.Addr(linux.HEMI_GVISOR_VMAR_START), make([]byte, test.length), linux.HEMI_GVISOR_RING_OP_READ,
				func(_ int32, enter *linux.HemiGvisorRingEnter) unix.Errno {
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
