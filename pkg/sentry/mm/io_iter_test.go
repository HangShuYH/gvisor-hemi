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

package mm

import (
	"bytes"
	"errors"
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/usermem"
)

type directIterTestAddressSpace struct {
	platform.AddressSpace
	streamUnavailable  bool
	streamTargetErr    error
	streamCopyOutCalls int
	streamCopyInCalls  int
	legacyCopyOutCalls int
	legacyCopyInCalls  int
	streamedOut        []byte
	streamedIn         []byte
}

func (*directIterTestAddressSpace) AddressSpaceIOAllSizes() bool {
	return true
}

func (*directIterTestAddressSpace) AddressSpaceIOApplicablePrefix(ar hostarch.AddrRange) (hostarch.Addr, bool) {
	return ar.Length(), true
}

func (as *directIterTestAddressSpace) CopyOut(addr hostarch.Addr, src []byte) (int, error) {
	as.legacyCopyOutCalls++
	return len(src), nil
}

func (as *directIterTestAddressSpace) CopyIn(addr hostarch.Addr, dst []byte) (int, error) {
	as.legacyCopyInCalls++
	copy(dst, as.streamedIn)
	return len(dst), nil
}

func (as *directIterTestAddressSpace) CopyOutFromIter(ars hostarch.AddrRangeSeq, src safemem.Reader) (int64, error) {
	as.streamCopyOutCalls++
	if as.streamUnavailable {
		return 0, platform.AddressSpaceIOUnavailable{}
	}
	if as.streamTargetErr != nil {
		return 0, &platform.AddressSpaceIOStreamError{Err: as.streamTargetErr}
	}
	buf := make([]byte, int(ars.NumBytes()))
	n, err := src.ReadToBlocks(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf)))
	as.streamedOut = append(as.streamedOut, buf[:n]...)
	return int64(n), err
}

func (as *directIterTestAddressSpace) CopyInToIter(ars hostarch.AddrRangeSeq, dst safemem.Writer) (int64, error) {
	as.streamCopyInCalls++
	if as.streamUnavailable {
		return 0, platform.AddressSpaceIOUnavailable{}
	}
	if as.streamTargetErr != nil {
		return 0, &platform.AddressSpaceIOStreamError{Err: as.streamTargetErr}
	}
	n, err := dst.WriteFromBlocks(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(as.streamedIn[:int(ars.NumBytes())])))
	return int64(n), err
}

func newDirectIterTestMemoryManager(as *directIterTestAddressSpace) *MemoryManager {
	return &MemoryManager{
		haveASIO: true,
		as:       as,
		layout:   arch.MmapLayout{MaxAddr: 0x10000},
	}
}

func TestAddressSpaceIOIterUsesPlatformBuffer(t *testing.T) {
	ars := hostarch.AddrRangeSeqOf(hostarch.AddrRange{Start: 0x5000, End: 0x5004})
	as := &directIterTestAddressSpace{streamedIn: []byte("wxyz")}
	mm := newDirectIterTestMemoryManager(as)

	reader := safemem.BlockSeqReader{Blocks: safemem.BlockSeqOf(safemem.BlockFromSafeSlice([]byte("abcd")))}
	if n, err := mm.CopyOutFromIter(context.Background(), ars, &reader, usermem.IOOpts{}); n != 4 || err != nil {
		t.Fatalf("CopyOutFromIter = (%d, %v), want (4, nil)", n, err)
	}
	if got := string(as.streamedOut); got != "abcd" || as.streamCopyOutCalls != 1 || as.legacyCopyOutCalls != 0 {
		t.Fatalf("streamed CopyOut = (%q, direct:%d, legacy:%d), want (abcd, 1, 0)", got, as.streamCopyOutCalls, as.legacyCopyOutCalls)
	}

	var got bytes.Buffer
	if n, err := mm.CopyInToIter(context.Background(), ars, safemem.FromIOWriter{Writer: &got}, usermem.IOOpts{}); n != 4 || err != nil {
		t.Fatalf("CopyInToIter = (%d, %v), want (4, nil)", n, err)
	}
	if got.String() != "wxyz" || as.streamCopyInCalls != 1 || as.legacyCopyInCalls != 0 {
		t.Fatalf("streamed CopyIn = (%q, direct:%d, legacy:%d), want (wxyz, 1, 0)", got.String(), as.streamCopyInCalls, as.legacyCopyInCalls)
	}
}

func TestAddressSpaceIOIterUnavailableFallsBackBeforeReader(t *testing.T) {
	ars := hostarch.AddrRangeSeqOf(hostarch.AddrRange{Start: 0x5000, End: 0x5004})
	as := &directIterTestAddressSpace{streamUnavailable: true}
	mm := newDirectIterTestMemoryManager(as)
	readerCalls := 0
	reader := safemem.ReaderFunc(func(dsts safemem.BlockSeq) (uint64, error) {
		readerCalls++
		return dsts.NumBytes(), nil
	})
	if n, err := mm.CopyOutFromIter(context.Background(), ars, reader, usermem.IOOpts{}); n != 4 || err != nil {
		t.Fatalf("fallback CopyOutFromIter = (%d, %v), want (4, nil)", n, err)
	}
	if readerCalls != 1 || as.streamCopyOutCalls != 1 || as.legacyCopyOutCalls != 1 {
		t.Fatalf("fallback calls = (reader:%d, direct:%d, legacy:%d), want (1, 1, 1)", readerCalls, as.streamCopyOutCalls, as.legacyCopyOutCalls)
	}
}

func TestAddressSpaceIOIterDistinguishesTargetAndSourceErrors(t *testing.T) {
	ars := hostarch.AddrRangeSeqOf(hostarch.AddrRange{Start: 0x5000, End: 0x5004})
	targetErr := errors.New("target error")
	as := &directIterTestAddressSpace{streamTargetErr: targetErr}
	mm := newDirectIterTestMemoryManager(as)
	reader := safemem.BlockSeqReader{Blocks: safemem.BlockSeqOf(safemem.BlockFromSafeSlice([]byte("abcd")))}
	if n, err := mm.CopyOutFromIter(context.Background(), ars, &reader, usermem.IOOpts{}); n != 0 || !linuxerr.Equals(linuxerr.EFAULT, err) {
		t.Fatalf("target error = (%d, %v), want (0, EFAULT)", n, err)
	}

	sourceErr := errors.New("source error")
	as = &directIterTestAddressSpace{}
	mm = newDirectIterTestMemoryManager(as)
	source := safemem.ReaderFunc(func(dsts safemem.BlockSeq) (uint64, error) {
		return 0, sourceErr
	})
	if n, err := mm.CopyOutFromIter(context.Background(), ars, source, usermem.IOOpts{}); n != 0 || !errors.Is(err, sourceErr) {
		t.Fatalf("source error = (%d, %v), want (0, source error)", n, err)
	}
}

func TestCopyOutFromIterStreamsAcrossAddrRanges(t *testing.T) {
	ars := hostarch.AddrRangeSeqFromSlice([]hostarch.AddrRange{
		{Start: 0x0800, End: 0x0800},
		{Start: 0x1000, End: 0x1003},
		{Start: 0x1800, End: 0x1800},
		{Start: 0x2000, End: 0x2005},
		{Start: 0x2800, End: 0x2800},
	})
	reader := safemem.BlockSeqReader{Blocks: safemem.BlockSeqOf(safemem.BlockFromSafeSlice([]byte("abcdefgh")))}
	readerCalls := 0
	maxRead := uint64(0)
	stream := safemem.ReaderFunc(func(dsts safemem.BlockSeq) (uint64, error) {
		readerCalls++
		maxRead = max(maxRead, dsts.NumBytes())
		return reader.ReadToBlocks(dsts)
	})

	written := make(map[hostarch.Addr]byte)
	done, err := copyOutFromIter(ars, stream, make([]byte, 4), func(ar hostarch.AddrRange, src []byte) (int, error) {
		for i, b := range src {
			written[ar.Start+hostarch.Addr(i)] = b
		}
		return len(src), nil
	})
	if err != nil || done != 8 {
		t.Fatalf("copyOutFromIter = (%d, %v), want (8, nil)", done, err)
	}
	if readerCalls != 2 || maxRead != 4 {
		t.Fatalf("Reader calls/max window = (%d, %d), want (2, 4)", readerCalls, maxRead)
	}
	want := map[hostarch.Addr]byte{
		0x1000: 'a', 0x1001: 'b', 0x1002: 'c',
		0x2000: 'd', 0x2001: 'e', 0x2002: 'f', 0x2003: 'g', 0x2004: 'h',
	}
	for addr, b := range want {
		if got := written[addr]; got != b {
			t.Errorf("byte at %#x = %q, want %q", addr, got, b)
		}
	}
}

func TestCopyInToIterStreamsAcrossAddrRanges(t *testing.T) {
	ars := hostarch.AddrRangeSeqFromSlice([]hostarch.AddrRange{
		{Start: 0x0800, End: 0x0800},
		{Start: 0x1000, End: 0x1003},
		{Start: 0x1800, End: 0x1800},
		{Start: 0x2000, End: 0x2005},
		{Start: 0x2800, End: 0x2800},
	})
	wantByAddr := map[hostarch.Addr]byte{
		0x1000: 'a', 0x1001: 'b', 0x1002: 'c',
		0x2000: 'd', 0x2001: 'e', 0x2002: 'f', 0x2003: 'g', 0x2004: 'h',
	}

	var got bytes.Buffer
	writerCalls := 0
	maxWrite := uint64(0)
	writer := safemem.WriterFunc(func(srcs safemem.BlockSeq) (uint64, error) {
		writerCalls++
		maxWrite = max(maxWrite, srcs.NumBytes())
		return safemem.FromIOWriter{Writer: &got}.WriteFromBlocks(srcs)
	})
	done, err := copyInToIter(ars, writer, make([]byte, 4), func(ar hostarch.AddrRange, dst []byte) (int, error) {
		for i := range dst {
			dst[i] = wantByAddr[ar.Start+hostarch.Addr(i)]
		}
		return len(dst), nil
	})
	if err != nil || done != 8 {
		t.Fatalf("copyInToIter = (%d, %v), want (8, nil)", done, err)
	}
	if writerCalls != 2 || maxWrite != 4 {
		t.Fatalf("Writer calls/max window = (%d, %d), want (2, 4)", writerCalls, maxWrite)
	}
	if want := "abcdefgh"; got.String() != want {
		t.Fatalf("copied data = %q, want %q", got.String(), want)
	}
}

func TestCopyOutFromIterTargetErrorWins(t *testing.T) {
	targetErr := errors.New("target fault")
	sourceErr := errors.New("source fault")
	reader := safemem.BlockSeqReader{Blocks: safemem.BlockSeqOf(safemem.BlockFromSafeSlice([]byte("ab")))}
	ars := hostarch.AddrRangeSeqOf(hostarch.AddrRange{Start: 0x1000, End: 0x1008})
	done, err := copyOutFromIter(ars, safemem.ReaderFunc(func(dsts safemem.BlockSeq) (uint64, error) {
		n, _ := reader.ReadToBlocks(dsts)
		return n, sourceErr
	}), make([]byte, 4), func(ar hostarch.AddrRange, src []byte) (int, error) {
		return 1, targetErr
	})
	if done != 1 || !errors.Is(err, targetErr) {
		t.Fatalf("copyOutFromIter = (%d, %v), want (1, target fault)", done, err)
	}
}

func TestCopyOutFromIterReaderPartialAndZeroProgress(t *testing.T) {
	sourceErr := errors.New("source fault")
	ars := hostarch.AddrRangeSeqOf(hostarch.AddrRange{Start: 0x1000, End: 0x1008})
	reader := safemem.BlockSeqReader{Blocks: safemem.BlockSeqOf(safemem.BlockFromSafeSlice([]byte("abc")))}
	done, err := copyOutFromIter(ars, safemem.ReaderFunc(func(dsts safemem.BlockSeq) (uint64, error) {
		n, _ := reader.ReadToBlocks(dsts)
		return n, sourceErr
	}), make([]byte, 4), func(ar hostarch.AddrRange, src []byte) (int, error) {
		return len(src), nil
	})
	if done != 3 || !errors.Is(err, sourceErr) {
		t.Fatalf("partial reader failure = (%d, %v), want (3, source fault)", done, err)
	}

	readerCalls := 0
	copyCalls := 0
	done, err = copyOutFromIter(ars, safemem.ReaderFunc(func(dsts safemem.BlockSeq) (uint64, error) {
		readerCalls++
		return 0, nil
	}), make([]byte, 4), func(ar hostarch.AddrRange, src []byte) (int, error) {
		copyCalls++
		return len(src), nil
	})
	if done != 0 || err != nil || readerCalls != 1 || copyCalls != 0 {
		t.Fatalf("zero-progress reader = (%d, %v, %d reader calls, %d copy calls), want (0, nil, 1, 0)", done, err, readerCalls, copyCalls)
	}
}

func TestCopyInToIterErrorPrecedence(t *testing.T) {
	targetErr := errors.New("target fault")
	writerErr := errors.New("writer fault")
	ars := hostarch.AddrRangeSeqOf(hostarch.AddrRange{Start: 0x1000, End: 0x1008})
	writer := safemem.WriterFunc(func(srcs safemem.BlockSeq) (uint64, error) {
		return 1, writerErr
	})
	done, err := copyInToIter(ars, writer, make([]byte, 4), func(ar hostarch.AddrRange, dst []byte) (int, error) {
		copy(dst, "abc")
		return 3, targetErr
	})
	if done != 1 || !errors.Is(err, writerErr) {
		t.Fatalf("copyInToIter writer failure = (%d, %v), want (1, writer fault)", done, err)
	}

	var got bytes.Buffer
	done, err = copyInToIter(ars, safemem.FromIOWriter{Writer: &got}, make([]byte, 4), func(ar hostarch.AddrRange, dst []byte) (int, error) {
		copy(dst, "abc")
		return 3, targetErr
	})
	if done != 3 || !errors.Is(err, targetErr) {
		t.Fatalf("copyInToIter target failure = (%d, %v), want (3, target fault)", done, err)
	}
	if got.String() != "abc" {
		t.Fatalf("copied prefix = %q, want %q", got.String(), "abc")
	}
}

func TestCopyInToIterShortWriterStops(t *testing.T) {
	ars := hostarch.AddrRangeSeqOf(hostarch.AddrRange{Start: 0x1000, End: 0x1008})
	writerCalls := 0
	done, err := copyInToIter(ars, safemem.WriterFunc(func(srcs safemem.BlockSeq) (uint64, error) {
		writerCalls++
		return 0, nil
	}), make([]byte, 4), func(ar hostarch.AddrRange, dst []byte) (int, error) {
		copy(dst, "abcd")
		return len(dst), nil
	})
	if done != 0 || err != nil || writerCalls != 1 {
		t.Fatalf("short writer = (%d, %v, %d calls), want (0, nil, 1)", done, err, writerCalls)
	}
}

func TestCopyOutFromIterValidatesIOVBeforeReader(t *testing.T) {
	mm := MemoryManager{layout: arch.MmapLayout{MaxAddr: 0x2000}}
	readerCalls := 0
	reader := safemem.ReaderFunc(func(dsts safemem.BlockSeq) (uint64, error) {
		readerCalls++
		return 0, nil
	})
	done, err := mm.CopyOutFromIter(
		context.Background(),
		hostarch.AddrRangeSeqFromSlice([]hostarch.AddrRange{
			{Start: 0x1000, End: 0x1001},
			{Start: 0x3000, End: 0x3001},
		}),
		reader,
		usermem.IOOpts{},
	)
	if done != 0 || err != linuxerr.EFAULT || readerCalls != 0 {
		t.Fatalf("invalid IOV = (%d, %v, %d reader calls), want (0, EFAULT, 0)", done, err, readerCalls)
	}
}

func TestCopyInToIterValidatesIOVBeforeWriter(t *testing.T) {
	mm := MemoryManager{layout: arch.MmapLayout{MaxAddr: 0x2000}}
	writerCalls := 0
	writer := safemem.WriterFunc(func(srcs safemem.BlockSeq) (uint64, error) {
		writerCalls++
		return 0, nil
	})
	done, err := mm.CopyInToIter(
		context.Background(),
		hostarch.AddrRangeSeqFromSlice([]hostarch.AddrRange{
			{Start: 0x1000, End: 0x1001},
			{Start: 0x3000, End: 0x3001},
		}),
		writer,
		usermem.IOOpts{},
	)
	if done != 0 || err != linuxerr.EFAULT || writerCalls != 0 {
		t.Fatalf("invalid IOV = (%d, %v, %d writer calls), want (0, EFAULT, 0)", done, err, writerCalls)
	}
}
