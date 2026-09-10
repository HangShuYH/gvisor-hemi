// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mm

import (
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/usermem"
)

type rangeAwareTestAddressSpace struct {
	platform.AddressSpace
	applicableRange     hostarch.AddrRange
	applicabilityCalls  int
	allSizesCalls       int
	sawEmptyRange       bool
	copyInCalls         int
	copyOutCalls        int
	zeroOutCalls        int
	ensureAccessCalls   int
	copyOutProgress     int
	swapCalls           int
	compareAndSwapCalls int
	loadCalls           int
}

func (as *rangeAwareTestAddressSpace) AddressSpaceIOApplicablePrefix(ar hostarch.AddrRange) (hostarch.Addr, bool) {
	as.applicabilityCalls++
	if ar.Length() == 0 {
		as.sawEmptyRange = true
		return 0, false
	}
	if ar.Start < as.applicableRange.Start {
		return min(ar.End, as.applicableRange.Start) - ar.Start, false
	}
	if ar.Start < as.applicableRange.End {
		return min(ar.End, as.applicableRange.End) - ar.Start, true
	}
	return ar.Length(), false
}

func (as *rangeAwareTestAddressSpace) AddressSpaceIOAllSizes() bool {
	as.allSizesCalls++
	return true
}

func TestASIOSizeCheckSkipsUnneededOverride(t *testing.T) {
	mm, as := newRangeAwareTestMemoryManager()
	if !mm.asioEnabledForSize(usermem.IOOpts{}, 512, copyMapMinBytes) || as.allSizesCalls != 0 {
		t.Fatal("small copy should qualify without querying the size override")
	}
	if !mm.asioEnabledForSize(usermem.IOOpts{}, copyMapMinBytes, copyMapMinBytes) || as.allSizesCalls != 1 {
		t.Fatal("copy at the threshold must query the size override")
	}
	if mm.asioEnabledForSize(usermem.IOOpts{IgnorePermissions: true}, 512, copyMapMinBytes) || as.allSizesCalls != 1 {
		t.Fatal("size must not bypass the permission policy")
	}
	mm.haveASIO = false
	if mm.asioEnabledForSize(usermem.IOOpts{}, 512, copyMapMinBytes) || as.allSizesCalls != 1 {
		t.Fatal("size must not enable an unavailable AddressSpaceIO")
	}
}

func (as *rangeAwareTestAddressSpace) CopyOut(addr hostarch.Addr, src []byte) (int, error) {
	as.copyOutCalls++
	if as.copyOutProgress != 0 {
		n := min(as.copyOutProgress, len(src))
		as.copyOutProgress = 0
		return n, platform.AddressSpaceIOUnavailable{}
	}
	return len(src), nil
}

func (as *rangeAwareTestAddressSpace) CopyIn(addr hostarch.Addr, dst []byte) (int, error) {
	as.copyInCalls++
	for i := range dst {
		dst[i] = 0x5a
	}
	return len(dst), nil
}

func (as *rangeAwareTestAddressSpace) ZeroOut(addr hostarch.Addr, toZero uintptr) (uintptr, error) {
	as.zeroOutCalls++
	return toZero, nil
}

func (as *rangeAwareTestAddressSpace) EnsureAccess(addr hostarch.Addr, length uint64, at hostarch.AccessType) (uint64, error) {
	as.ensureAccessCalls++
	return length, nil
}

func (as *rangeAwareTestAddressSpace) SwapUint32(addr hostarch.Addr, new uint32) (uint32, error) {
	as.swapCalls++
	return 1, nil
}

func (as *rangeAwareTestAddressSpace) CompareAndSwapUint32(addr hostarch.Addr, old, new uint32) (uint32, error) {
	as.compareAndSwapCalls++
	return old, nil
}

func (as *rangeAwareTestAddressSpace) LoadUint32(addr hostarch.Addr) (uint32, error) {
	as.loadCalls++
	return 2, nil
}

func newRangeAwareTestMemoryManager() (*MemoryManager, *rangeAwareTestAddressSpace) {
	as := &rangeAwareTestAddressSpace{
		applicableRange: hostarch.AddrRange{Start: 0x5000, End: 0x7000},
	}
	return &MemoryManager{
		haveASIO: true,
		as:       as,
		layout:   arch.MmapLayout{MaxAddr: 0x10000},
	}, as
}

func TestRangeAwareASIOSkipsInapplicableBufferedIO(t *testing.T) {
	tests := []struct {
		name string
		size hostarch.Addr
	}{
		{name: "256_bytes", size: 256},
		{name: "1024_bytes", size: 1024},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ars := hostarch.AddrRangeSeqOf(hostarch.AddrRange{Start: 0x1000, End: 0x1000 + test.size})

			mm, as := newRangeAwareTestMemoryManager()
			readerCalls := 0
			reader := safemem.ReaderFunc(func(dsts safemem.BlockSeq) (uint64, error) {
				readerCalls++
				return dsts.NumBytes(), nil
			})
			if n, err := mm.CopyOutFrom(context.Background(), ars, reader, usermem.IOOpts{}); n != 0 || !linuxerr.Equals(linuxerr.EFAULT, err) {
				t.Fatalf("CopyOutFrom outside ASIO range = (%d, %v), want (0, EFAULT)", n, err)
			}
			if readerCalls != 0 || as.copyOutCalls != 0 {
				t.Fatalf("CopyOutFrom outside ASIO range called Reader/AddressSpace %d/%d times, want 0/0", readerCalls, as.copyOutCalls)
			}

			mm, as = newRangeAwareTestMemoryManager()
			writerCalls := 0
			writer := safemem.WriterFunc(func(srcs safemem.BlockSeq) (uint64, error) {
				writerCalls++
				return srcs.NumBytes(), nil
			})
			if n, err := mm.CopyInTo(context.Background(), ars, writer, usermem.IOOpts{}); n != 0 || !linuxerr.Equals(linuxerr.EFAULT, err) {
				t.Fatalf("CopyInTo outside ASIO range = (%d, %v), want (0, EFAULT)", n, err)
			}
			if writerCalls != 0 || as.copyInCalls != 0 {
				t.Fatalf("CopyInTo outside ASIO range called Writer/AddressSpace %d/%d times, want 0/0", writerCalls, as.copyInCalls)
			}
		})
	}
}

func TestRangeAwareASIOStillHandlesApplicableBufferedIO(t *testing.T) {
	const size = hostarch.Addr(4096)
	ars := hostarch.AddrRangeSeqOf(hostarch.AddrRange{Start: 0x5000, End: 0x5000 + size})

	mm, as := newRangeAwareTestMemoryManager()
	readerCalls := 0
	reader := safemem.ReaderFunc(func(dsts safemem.BlockSeq) (uint64, error) {
		readerCalls++
		return dsts.NumBytes(), nil
	})
	if n, err := mm.CopyOutFrom(context.Background(), ars, reader, usermem.IOOpts{}); n != int64(size) || err != nil {
		t.Fatalf("CopyOutFrom inside ASIO range = (%d, %v), want (%d, nil)", n, err, size)
	}
	if readerCalls != 1 || as.copyOutCalls != 1 {
		t.Fatalf("CopyOutFrom inside ASIO range called Reader/AddressSpace %d/%d times, want 1/1", readerCalls, as.copyOutCalls)
	}

	mm, as = newRangeAwareTestMemoryManager()
	writerCalls := 0
	writer := safemem.WriterFunc(func(srcs safemem.BlockSeq) (uint64, error) {
		writerCalls++
		for srcs.NumBytes() != 0 {
			block := srcs.Head()
			for _, b := range block.ToSlice() {
				if b != 0x5a {
					t.Fatalf("CopyInTo received byte %#x, want 0x5a", b)
				}
			}
			srcs = srcs.Tail()
		}
		return uint64(size), nil
	})
	if n, err := mm.CopyInTo(context.Background(), ars, writer, usermem.IOOpts{}); n != int64(size) || err != nil {
		t.Fatalf("CopyInTo inside ASIO range = (%d, %v), want (%d, nil)", n, err, size)
	}
	if writerCalls != 1 || as.copyInCalls != 1 {
		t.Fatalf("CopyInTo inside ASIO range called Writer/AddressSpace %d/%d times, want 1/1", writerCalls, as.copyInCalls)
	}
}

func TestRangeAwareASIOAppliesToAnyNonEmptyRange(t *testing.T) {
	mm, as := newRangeAwareTestMemoryManager()
	ars := hostarch.AddrRangeSeqFromSlice([]hostarch.AddrRange{
		{Start: 0x1000, End: 0x1100},
		{Start: 0x2000, End: 0x2000},
		{Start: 0x5000, End: 0x5100},
	})
	if !mm.asioApplicableToAny(ars) {
		t.Fatal("mixed IOV did not select AddressSpaceIO")
	}
	if as.sawEmptyRange {
		t.Fatal("range applicability was queried for an empty range")
	}
}

func TestRangeAwareASIOSplitsAtBoundary(t *testing.T) {
	const (
		start = hostarch.Addr(0x6000)
		size  = 0x2000
		want  = 0x1000
	)

	mm, as := newRangeAwareTestMemoryManager()
	if n, err := mm.CopyOut(context.Background(), start, make([]byte, size), usermem.IOOpts{}); n != want || !linuxerr.Equals(linuxerr.EFAULT, err) {
		t.Fatalf("CopyOut crossing ASIO end = (%d, %v), want (%d, EFAULT)", n, err, want)
	}
	if as.copyOutCalls != 1 {
		t.Fatalf("CopyOut crossing ASIO end made %d AddressSpace calls, want 1", as.copyOutCalls)
	}

	mm, as = newRangeAwareTestMemoryManager()
	if n, err := mm.CopyIn(context.Background(), start, make([]byte, size), usermem.IOOpts{}); n != want || !linuxerr.Equals(linuxerr.EFAULT, err) {
		t.Fatalf("CopyIn crossing ASIO end = (%d, %v), want (%d, EFAULT)", n, err, want)
	}
	if as.copyInCalls != 1 {
		t.Fatalf("CopyIn crossing ASIO end made %d AddressSpace calls, want 1", as.copyInCalls)
	}

	mm, as = newRangeAwareTestMemoryManager()
	if n, err := mm.ZeroOut(context.Background(), start, size, usermem.IOOpts{}); n != want || !linuxerr.Equals(linuxerr.EFAULT, err) {
		t.Fatalf("ZeroOut crossing ASIO end = (%d, %v), want (%d, EFAULT)", n, err, want)
	}
	if as.zeroOutCalls != 1 {
		t.Fatalf("ZeroOut crossing ASIO end made %d AddressSpace calls, want 1", as.zeroOutCalls)
	}

	mm, as = newRangeAwareTestMemoryManager()
	if n, err := mm.EnsurePMAsExist(context.Background(), start, size, usermem.IOOpts{}); n != want || !linuxerr.Equals(linuxerr.EFAULT, err) {
		t.Fatalf("EnsurePMAsExist crossing ASIO end = (%d, %v), want (%d, EFAULT)", n, err, want)
	}
	if as.ensureAccessCalls != 1 {
		t.Fatalf("EnsurePMAsExist crossing ASIO end made %d AddressSpace calls, want 1", as.ensureAccessCalls)
	}

	mm, as = newRangeAwareTestMemoryManager()
	if n, err := mm.CopyOut(context.Background(), 0x4000, make([]byte, size), usermem.IOOpts{}); n != 0 || !linuxerr.Equals(linuxerr.EFAULT, err) {
		t.Fatalf("CopyOut crossing ASIO start = (%d, %v), want (0, EFAULT)", n, err)
	}
	if as.copyOutCalls != 0 {
		t.Fatalf("CopyOut crossing ASIO start made %d AddressSpace calls before the internal prefix, want 0", as.copyOutCalls)
	}
}

func TestRangeAwareASIOSkipsEmptyIOVInBufferedLoop(t *testing.T) {
	ars := hostarch.AddrRangeSeqFromSlice([]hostarch.AddrRange{
		{Start: 0x5000, End: 0x5100},
		{Start: 0x5200, End: 0x5200},
		{Start: 0x5300, End: 0x5400},
	})

	mm, as := newRangeAwareTestMemoryManager()
	reader := safemem.ReaderFunc(func(dsts safemem.BlockSeq) (uint64, error) {
		return dsts.NumBytes(), nil
	})
	if n, err := mm.CopyOutFrom(context.Background(), ars, reader, usermem.IOOpts{}); n != 0x200 || err != nil {
		t.Fatalf("CopyOutFrom with empty IOV = (%d, %v), want (512, nil)", n, err)
	}
	if as.copyOutCalls != 2 || as.sawEmptyRange {
		t.Fatalf("CopyOutFrom with empty IOV made %d AddressSpace calls, sawEmpty=%t; want 2, false", as.copyOutCalls, as.sawEmptyRange)
	}

	mm, as = newRangeAwareTestMemoryManager()
	writer := safemem.WriterFunc(func(srcs safemem.BlockSeq) (uint64, error) {
		return srcs.NumBytes(), nil
	})
	if n, err := mm.CopyInTo(context.Background(), ars, writer, usermem.IOOpts{}); n != 0x200 || err != nil {
		t.Fatalf("CopyInTo with empty IOV = (%d, %v), want (512, nil)", n, err)
	}
	if as.copyInCalls != 2 || as.sawEmptyRange {
		t.Fatalf("CopyInTo with empty IOV made %d AddressSpace calls, sawEmpty=%t; want 2, false", as.copyInCalls, as.sawEmptyRange)
	}
}

func TestRangeAwareASIOFallbackPreservesProgress(t *testing.T) {
	mm, as := newRangeAwareTestMemoryManager()
	as.copyOutProgress = 128
	if n, err := mm.CopyOut(context.Background(), 0x5000, make([]byte, 256), usermem.IOOpts{}); n != 128 || !linuxerr.Equals(linuxerr.EFAULT, err) {
		t.Fatalf("partial CopyOut fallback = (%d, %v), want (128, EFAULT)", n, err)
	}
}

func TestRangeAwareASIOAtomicRouting(t *testing.T) {
	ctx := context.Background()

	mm, as := newRangeAwareTestMemoryManager()
	if old, err := mm.SwapUint32(ctx, 0x5000, 3, usermem.IOOpts{}); old != 1 || err != nil {
		t.Fatalf("SwapUint32 inside ASIO range = (%d, %v), want (1, nil)", old, err)
	}
	if as.swapCalls != 1 {
		t.Fatalf("SwapUint32 inside ASIO range made %d AddressSpace calls, want 1", as.swapCalls)
	}

	mm, as = newRangeAwareTestMemoryManager()
	if prev, err := mm.CompareAndSwapUint32(ctx, 0x5000, 4, 5, usermem.IOOpts{}); prev != 4 || err != nil {
		t.Fatalf("CompareAndSwapUint32 inside ASIO range = (%d, %v), want (4, nil)", prev, err)
	}
	if as.compareAndSwapCalls != 1 {
		t.Fatalf("CompareAndSwapUint32 inside ASIO range made %d AddressSpace calls, want 1", as.compareAndSwapCalls)
	}

	mm, as = newRangeAwareTestMemoryManager()
	if value, err := mm.LoadUint32(ctx, 0x1000, usermem.IOOpts{}); value != 0 || !linuxerr.Equals(linuxerr.EFAULT, err) {
		t.Fatalf("LoadUint32 outside ASIO range = (%d, %v), want (0, EFAULT)", value, err)
	}
	if as.loadCalls != 0 {
		t.Fatalf("LoadUint32 outside ASIO range made %d AddressSpace calls, want 0", as.loadCalls)
	}

	mm, as = newRangeAwareTestMemoryManager()
	if value, err := mm.LoadUint32(ctx, 0x4fff, usermem.IOOpts{}); value != 0 || !linuxerr.Equals(linuxerr.EFAULT, err) {
		t.Fatalf("LoadUint32 crossing ASIO boundary = (%d, %v), want (0, EFAULT)", value, err)
	}
	if as.loadCalls != 0 {
		t.Fatalf("LoadUint32 crossing ASIO boundary made %d AddressSpace calls, want 0", as.loadCalls)
	}
}
