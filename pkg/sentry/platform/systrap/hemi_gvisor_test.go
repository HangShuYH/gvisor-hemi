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
	"math"
	"testing"

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
