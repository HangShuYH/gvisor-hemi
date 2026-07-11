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
	"testing"

	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

func TestFindAvailableAvoidsReservedRange(t *testing.T) {
	const page = uint64(hostarch.PageSize)
	reserved := hostarch.AddrRange{Start: 0x5000, End: 0x9000}

	tests := []struct {
		name       string
		layout     arch.MmapLayout
		opts       findAvailableOpts
		length     uint64
		want       hostarch.Addr
		wantENOMEM bool
	}{
		{
			name:   "hint in reserved range",
			layout: arch.MmapLayout{MinAddr: 0x1000, MaxAddr: 0xb000, BottomUpBase: 0x4000, TopDownBase: 0xb000, DefaultDirection: arch.MmapBottomUp},
			opts:   findAvailableOpts{Addr: 0x6000},
			length: page,
			want:   0x4000,
		},
		{
			name:   "bottom up skips reserved range",
			layout: arch.MmapLayout{MinAddr: 0x1000, MaxAddr: 0xb000, BottomUpBase: 0x4000, TopDownBase: 0xb000, DefaultDirection: arch.MmapBottomUp},
			length: 2 * page,
			want:   0x9000,
		},
		{
			name:   "top down skips reserved range",
			layout: arch.MmapLayout{MinAddr: 0x3000, MaxAddr: 0xb000, BottomUpBase: 0x3000, TopDownBase: 0xa000, DefaultDirection: arch.MmapTopDown},
			length: 2 * page,
			want:   0x3000,
		},
		{
			name:       "fixed in reserved range",
			layout:     arch.MmapLayout{MinAddr: 0x1000, MaxAddr: 0xb000, BottomUpBase: 0x1000, TopDownBase: 0xb000, DefaultDirection: arch.MmapBottomUp},
			opts:       findAvailableOpts{Addr: 0x6000, Fixed: true},
			length:     page,
			wantENOMEM: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mm := MemoryManager{layout: test.layout, reservedAR: reserved}
			mm.mappingMu.Lock()
			got, err := mm.findAvailableLocked(test.length, test.opts)
			mm.mappingMu.Unlock()
			if test.wantENOMEM && !linuxerr.Equals(linuxerr.ENOMEM, err) {
				t.Fatalf("findAvailableLocked() error = %v, want %v", err, linuxerr.ENOMEM)
			}
			if !test.wantENOMEM && err != nil {
				t.Fatalf("findAvailableLocked() unexpected error: %v", err)
			}
			if got != test.want {
				t.Fatalf("findAvailableLocked() = %#x, want %#x", got, test.want)
			}
		})
	}
}

func TestForceMMapCannotUseReservedRange(t *testing.T) {
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	defer mm.DecUsers(ctx)

	mm.reservedAR = hostarch.AddrRange{Start: 0x50000000, End: 0x50001000}
	_, err := mm.MMap(ctx, memmap.MMapOpts{
		Force:    true,
		Unmap:    true,
		Fixed:    true,
		Addr:     mm.reservedAR.Start,
		Length:   hostarch.PageSize,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if !linuxerr.Equals(linuxerr.ENOMEM, err) {
		t.Fatalf("MMap() error = %v, want %v", err, linuxerr.ENOMEM)
	}
}
