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
	"sync/atomic"
	"testing"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/usermem"
)

type forkTrackingPlatform struct {
	platform.Platform
	addressSpaces []*forkTrackingAddressSpace
}

func (p *forkTrackingPlatform) NewAddressSpace() (platform.AddressSpace, error) {
	as, err := p.Platform.NewAddressSpace()
	if err != nil {
		return nil, err
	}
	tracked := &forkTrackingAddressSpace{AddressSpace: as}
	p.addressSpaces = append(p.addressSpaces, tracked)
	return tracked, nil
}

type forkTrackingAddressSpace struct {
	platform.AddressSpace
	forkSource                      platform.AddressSpace
	ensureAddr                      hostarch.Addr
	ensureLength                    uint64
	ensureAccess                    hostarch.AccessType
	ignorePermissionsRead           bool
	copyInCalls                     int
	copyOutCalls                    int
	copyOutIgnoringPermissionsCalls int
	copyInData                      []byte
	atomicValue                     uint32
	swapUint32Calls                 int
	compareAndSwapCalls             int
	loadUint32Calls                 int
}

func (as *forkTrackingAddressSpace) ForkAddressSpaceFrom(source platform.AddressSpace) error {
	as.forkSource = source
	return nil
}

func (as *forkTrackingAddressSpace) EnsureAccess(addr hostarch.Addr, length uint64, at hostarch.AccessType) (uint64, error) {
	as.ensureAddr = addr
	as.ensureLength = length
	as.ensureAccess = at
	return length, nil
}

func (as *forkTrackingAddressSpace) AddressSpaceIOReadIgnoresPermissions() bool {
	return as.ignorePermissionsRead
}

func (as *forkTrackingAddressSpace) CopyIn(addr hostarch.Addr, dst []byte) (int, error) {
	as.copyInCalls++
	return copy(dst, as.copyInData), nil
}

func (as *forkTrackingAddressSpace) CopyOut(addr hostarch.Addr, src []byte) (int, error) {
	as.copyOutCalls++
	return len(src), nil
}

func (as *forkTrackingAddressSpace) CopyOutIgnoringPermissions(addr hostarch.Addr, src []byte) (int, error) {
	as.copyOutIgnoringPermissionsCalls++
	return len(src), nil
}

func (as *forkTrackingAddressSpace) SwapUint32(addr hostarch.Addr, new uint32) (uint32, error) {
	as.swapUint32Calls++
	return atomic.SwapUint32(&as.atomicValue, new), nil
}

func (as *forkTrackingAddressSpace) CompareAndSwapUint32(addr hostarch.Addr, old, new uint32) (uint32, error) {
	as.compareAndSwapCalls++
	for {
		prev := atomic.LoadUint32(&as.atomicValue)
		if prev != old || atomic.CompareAndSwapUint32(&as.atomicValue, old, new) {
			return prev, nil
		}
	}
}

func (as *forkTrackingAddressSpace) LoadUint32(addr hostarch.Addr) (uint32, error) {
	as.loadUint32Calls++
	return atomic.LoadUint32(&as.atomicValue), nil
}

func TestForkCopiesPlatformAddressSpaceState(t *testing.T) {
	ctx := contexttest.Context(t)
	p := &forkTrackingPlatform{Platform: platform.FromContext(ctx)}
	parent, err := NewMemoryManager(p, pgalloc.MemoryFileFromContext(ctx))
	if err != nil {
		t.Fatalf("NewMemoryManager: %v", err)
	}
	defer parent.DecUsers(ctx)

	child, err := parent.Fork(ctx)
	if err != nil {
		t.Fatalf("MemoryManager.Fork: %v", err)
	}
	defer child.DecUsers(ctx)

	if got, want := len(p.addressSpaces), 2; got != want {
		t.Fatalf("created %d address spaces, want %d", got, want)
	}
	if got, want := p.addressSpaces[1].forkSource, platform.AddressSpace(p.addressSpaces[0]); got != want {
		t.Fatalf("child fork source is %p, want parent %p", got, want)
	}
}

func TestEnsurePMAsExistUsesPlatformAccessCheck(t *testing.T) {
	ctx := contexttest.Context(t)
	p := &forkTrackingPlatform{Platform: platform.FromContext(ctx)}
	mm, err := NewMemoryManager(p, pgalloc.MemoryFileFromContext(ctx))
	if err != nil {
		t.Fatalf("NewMemoryManager: %v", err)
	}
	defer mm.DecUsers(ctx)
	mm.haveASIO = true
	mm.layout.MaxAddr = p.MaxUserAddress()

	const length = int64(2 * hostarch.PageSize)
	addr := p.MinUserAddress() + 10*hostarch.PageSize
	n, err := mm.EnsurePMAsExist(ctx, addr, length, usermem.IOOpts{})
	if err != nil {
		t.Fatalf("EnsurePMAsExist: %v", err)
	}
	if n != length {
		t.Fatalf("EnsurePMAsExist returned %d bytes, want %d", n, length)
	}
	as := p.addressSpaces[0]
	if as.ensureAddr != addr || as.ensureLength != uint64(length) || as.ensureAccess != hostarch.Write {
		t.Fatalf("EnsureAccess(%#x, %d, %v), want (%#x, %d, %v)",
			as.ensureAddr, as.ensureLength, as.ensureAccess,
			addr, length, hostarch.Write)
	}
}

func TestCopyInIgnorePermissionsUsesCapableAddressSpace(t *testing.T) {
	ctx := contexttest.Context(t)
	p := &forkTrackingPlatform{Platform: platform.FromContext(ctx)}
	mm, err := NewMemoryManager(p, pgalloc.MemoryFileFromContext(ctx))
	if err != nil {
		t.Fatalf("NewMemoryManager: %v", err)
	}
	defer mm.DecUsers(ctx)

	mm.haveASIO = true
	mm.layout.MaxAddr = p.MaxUserAddress()
	as := p.addressSpaces[0]
	as.ignorePermissionsRead = true
	as.copyInData = []byte{0x0f, 0xa2}

	got := make([]byte, len(as.copyInData))
	if n, err := mm.CopyIn(ctx, p.MinUserAddress(), got, usermem.IOOpts{IgnorePermissions: true}); err != nil {
		t.Fatalf("CopyIn: %v", err)
	} else if n != len(got) {
		t.Fatalf("CopyIn copied %d bytes, want %d", n, len(got))
	}
	if as.copyInCalls != 1 {
		t.Fatalf("AddressSpace.CopyIn called %d times, want 1", as.copyInCalls)
	}
	if got[0] != 0x0f || got[1] != 0xa2 {
		t.Fatalf("CopyIn returned %x, want 0fa2", got)
	}
}

func TestCopyOutIgnorePermissionsUsesCapableAddressSpace(t *testing.T) {
	ctx := contexttest.Context(t)
	p := &forkTrackingPlatform{Platform: platform.FromContext(ctx)}
	mm, err := NewMemoryManager(p, pgalloc.MemoryFileFromContext(ctx))
	if err != nil {
		t.Fatalf("NewMemoryManager: %v", err)
	}
	defer mm.DecUsers(ctx)

	mm.haveASIO = true
	mm.layout.MaxAddr = p.MaxUserAddress()
	as := p.addressSpaces[0]
	data := []byte{0xff, 0x24, 0x25}
	if n, err := mm.CopyOut(ctx, p.MinUserAddress(), data, usermem.IOOpts{IgnorePermissions: true}); err != nil {
		t.Fatalf("CopyOut: %v", err)
	} else if n != len(data) {
		t.Fatalf("CopyOut copied %d bytes, want %d", n, len(data))
	}
	if as.copyOutIgnoringPermissionsCalls != 1 {
		t.Fatalf("AddressSpace.CopyOutIgnoringPermissions called %d times, want 1", as.copyOutIgnoringPermissionsCalls)
	}
	if as.copyOutCalls != 0 {
		t.Fatalf("AddressSpace.CopyOut called %d times, want 0", as.copyOutCalls)
	}
}

func TestAtomicUint32UsesAddressSpaceIO(t *testing.T) {
	ctx := contexttest.Context(t)
	p := &forkTrackingPlatform{Platform: platform.FromContext(ctx)}
	mm, err := NewMemoryManager(p, pgalloc.MemoryFileFromContext(ctx))
	if err != nil {
		t.Fatalf("NewMemoryManager: %v", err)
	}
	defer mm.DecUsers(ctx)

	mm.haveASIO = true
	mm.layout.MaxAddr = p.MaxUserAddress()
	as := p.addressSpaces[0]
	addr := p.MinUserAddress()
	atomic.StoreUint32(&as.atomicValue, 7)

	if old, err := mm.SwapUint32(ctx, addr, 11, usermem.IOOpts{}); err != nil {
		t.Fatalf("SwapUint32: %v", err)
	} else if old != 7 {
		t.Fatalf("SwapUint32 returned %d, want 7", old)
	}
	if prev, err := mm.CompareAndSwapUint32(ctx, addr, 11, 13, usermem.IOOpts{}); err != nil {
		t.Fatalf("CompareAndSwapUint32 success: %v", err)
	} else if prev != 11 {
		t.Fatalf("CompareAndSwapUint32 success returned %d, want 11", prev)
	}
	if prev, err := mm.CompareAndSwapUint32(ctx, addr, 11, 17, usermem.IOOpts{}); err != nil {
		t.Fatalf("CompareAndSwapUint32 failure: %v", err)
	} else if prev != 13 {
		t.Fatalf("CompareAndSwapUint32 failure returned %d, want 13", prev)
	}
	if value, err := mm.LoadUint32(ctx, addr, usermem.IOOpts{}); err != nil {
		t.Fatalf("LoadUint32: %v", err)
	} else if value != 13 {
		t.Fatalf("LoadUint32 returned %d, want 13", value)
	}

	if as.swapUint32Calls != 1 || as.compareAndSwapCalls != 2 || as.loadUint32Calls != 1 {
		t.Fatalf("AddressSpace atomic calls = swap:%d cas:%d load:%d, want 1/2/1",
			as.swapUint32Calls, as.compareAndSwapCalls, as.loadUint32Calls)
	}
	if as.copyInCalls != 0 || as.copyOutCalls != 0 {
		t.Fatalf("atomic operations used CopyIn/CopyOut %d/%d times, want 0/0",
			as.copyInCalls, as.copyOutCalls)
	}
}
