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
	forkSource            platform.AddressSpace
	ensureAddr            hostarch.Addr
	ensureLength          uint64
	ensureAccess          hostarch.AccessType
	ignorePermissionsRead bool
	copyInCalls           int
	copyInData            []byte
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
