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
	"errors"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

type initializerTrackingPlatform struct {
	platform.Platform
	initErr       error
	addressSpaces []*initializerTrackingAddressSpace
}

func (p *initializerTrackingPlatform) NewAddressSpace() (platform.AddressSpace, error) {
	as, err := p.Platform.NewAddressSpace()
	if err != nil {
		return nil, err
	}
	tracked := &initializerTrackingAddressSpace{
		AddressSpace: as,
		initErr:      p.initErr,
	}
	p.addressSpaces = append(p.addressSpaces, tracked)
	return tracked, nil
}

type initializerTrackingAddressSpace struct {
	platform.AddressSpace
	initErr         error
	initializeCalls int
	forkCalls       int
	releaseCalls    int
	forkSource      platform.AddressSpace
}

func (as *initializerTrackingAddressSpace) InitializeAddressSpace() error {
	as.initializeCalls++
	return as.initErr
}

func (as *initializerTrackingAddressSpace) ForkAddressSpaceFrom(source platform.AddressSpace) error {
	as.forkCalls++
	as.forkSource = source
	return nil
}

func (as *initializerTrackingAddressSpace) Release() {
	as.releaseCalls++
	as.AddressSpace.Release()
}

func TestAddressSpaceInitializeAndForkAreMutuallyExclusive(t *testing.T) {
	ctx := contexttest.Context(t)
	p := &initializerTrackingPlatform{Platform: platform.FromContext(ctx)}
	parent, err := NewMemoryManager(p, pgalloc.MemoryFileFromContext(ctx))
	if err != nil {
		t.Fatalf("NewMemoryManager: %v", err)
	}
	defer parent.DecUsers(ctx)

	if got := p.addressSpaces[0].initializeCalls; got != 1 {
		t.Fatalf("parent initialize calls = %d, want 1", got)
	}
	child, err := parent.Fork(ctx)
	if err != nil {
		t.Fatalf("Fork: %v", err)
	}
	defer child.DecUsers(ctx)

	childAS := p.addressSpaces[1]
	if childAS.initializeCalls != 0 || childAS.forkCalls != 1 {
		t.Fatalf("child initialize/fork calls = %d/%d, want 0/1",
			childAS.initializeCalls, childAS.forkCalls)
	}
	if childAS.forkSource != p.addressSpaces[0] {
		t.Fatalf("fork source = %T %p, want parent %p",
			childAS.forkSource, childAS.forkSource, p.addressSpaces[0])
	}
}

func TestAddressSpaceInitializeFailureReleasesAddressSpace(t *testing.T) {
	ctx := contexttest.Context(t)
	wantErr := errors.New("initializer failure")
	p := &initializerTrackingPlatform{
		Platform: platform.FromContext(ctx),
		initErr:  wantErr,
	}
	if _, err := NewMemoryManager(p, pgalloc.MemoryFileFromContext(ctx)); !errors.Is(err, wantErr) {
		t.Fatalf("NewMemoryManager error = %v, want %v", err, wantErr)
	}
	if got := p.addressSpaces[0].releaseCalls; got != 1 {
		t.Fatalf("release calls after initializer failure = %d, want 1", got)
	}
}
