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

package linux

import "structs"

const (
	HEMI_GVISOR_IOCTL_TYPE = uint32('H')
	HEMI_GVISOR_RING_ABI   = uint32(1)
	HEMI_GVISOR_RING_MAGIC = uint64(0x48454d4952494e47)

	// HEMI_GVISOR_VMAR_START and HEMI_GVISOR_VMAR_END define the half-open
	// user virtual-address range managed by HEMI.
	HEMI_GVISOR_VMAR_START = uint64(0x0000610000000000)
	HEMI_GVISOR_VMAR_END   = uint64(0x0000620000000000)
)

// HemiGvisorMapFile is struct hemi_gvisor_map_file from
// include/uapi/linux/hemi_gvisor.h.
//
// +marshal
type HemiGvisorMapFile struct {
	_           structs.HostLayout
	Addr        uint64
	Len         uint64
	Prot        uint64
	Flags       uint64
	GuestFD     int64
	GuestOffset uint64
	HostFD      int64
	HostOffset  uint64
}

var (
	HEMI_GVISOR_MAP_FILE = IOW(HEMI_GVISOR_IOCTL_TYPE, 0x01, uint32((*HemiGvisorMapFile)(nil).SizeBytes()))
)

// HemiGvisorAllocMM is struct hemi_gvisor_alloc_mm from
// include/uapi/linux/hemi_gvisor.h.
//
// +marshal
type HemiGvisorAllocMM struct {
	_              structs.HostLayout
	TargetTGID     int32
	TargetDeviceFD int32
	Flags          uint32
	Reserved       uint32
	MMHandle       uint64
}

// HemiGvisorForkMM is struct hemi_gvisor_fork_mm from
// include/uapi/linux/hemi_gvisor.h.
//
// +marshal
type HemiGvisorForkMM struct {
	_              structs.HostLayout
	ParentMMHandle uint64
	TargetTGID     int32
	TargetDeviceFD int32
	Flags          uint32
	Reserved       uint32
	ChildMMHandle  uint64
}

// HemiGvisorFreeMM is struct hemi_gvisor_free_mm from
// include/uapi/linux/hemi_gvisor.h.
//
// +marshal
type HemiGvisorFreeMM struct {
	_        structs.HostLayout
	MMHandle uint64
	Flags    uint32
	Reserved uint32
}

var (
	HEMI_GVISOR_ALLOC_MM = IOWR(HEMI_GVISOR_IOCTL_TYPE, 0x02, uint32((*HemiGvisorAllocMM)(nil).SizeBytes()))
	HEMI_GVISOR_FORK_MM  = IOWR(HEMI_GVISOR_IOCTL_TYPE, 0x03, uint32((*HemiGvisorForkMM)(nil).SizeBytes()))
	HEMI_GVISOR_FREE_MM  = IOW(HEMI_GVISOR_IOCTL_TYPE, 0x04, uint32((*HemiGvisorFreeMM)(nil).SizeBytes()))
)

// HemiGvisorUserMem is struct hemi_gvisor_user_mem from
// include/uapi/linux/hemi_gvisor.h.
//
// +marshal
type HemiGvisorUserMem struct {
	_        structs.HostLayout
	Addr     uint64
	Len      uint64
	UserBuf  uint64
	MMHandle uint64
	Done     uint64
	Result   int32
	Flags    uint32
}

var (
	HEMI_GVISOR_READ_USER  = IOWR(HEMI_GVISOR_IOCTL_TYPE, 0x11, uint32((*HemiGvisorUserMem)(nil).SizeBytes()))
	HEMI_GVISOR_WRITE_USER = IOWR(HEMI_GVISOR_IOCTL_TYPE, 0x12, uint32((*HemiGvisorUserMem)(nil).SizeBytes()))
)

const (
	HEMI_GVISOR_ATOMIC_U32_LOAD    = 0
	HEMI_GVISOR_ATOMIC_U32_SWAP    = 1
	HEMI_GVISOR_ATOMIC_U32_CMPXCHG = 2
)

// HemiGvisorAtomicU32 is struct hemi_gvisor_atomic_u32 from
// include/uapi/linux/hemi_gvisor.h.
//
// +marshal
type HemiGvisorAtomicU32 struct {
	_        structs.HostLayout
	Addr     uint64
	MMHandle uint64
	Op       uint32
	Old      uint32
	New      uint32
	Value    uint32
	Flags    uint32
	Reserved uint32
}

var (
	HEMI_GVISOR_ATOMIC_U32 = IOWR(HEMI_GVISOR_IOCTL_TYPE, 0x13, uint32((*HemiGvisorAtomicU32)(nil).SizeBytes()))
)

const (
	HEMI_GVISOR_USER_ACCESS_READ  = 1
	HEMI_GVISOR_USER_ACCESS_WRITE = 2
)

// HemiGvisorProbeUser is struct hemi_gvisor_probe_user from
// include/uapi/linux/hemi_gvisor.h.
//
// +marshal
type HemiGvisorProbeUser struct {
	_        structs.HostLayout
	Addr     uint64
	Len      uint64
	Done     uint64
	MMHandle uint64
	Access   uint32
	Result   int32
	Flags    uint32
	Reserved uint32
}

var (
	HEMI_GVISOR_PROBE_USER = IOWR(HEMI_GVISOR_IOCTL_TYPE, 0x14, uint32((*HemiGvisorProbeUser)(nil).SizeBytes()))
)

// HemiGvisorRingSetup is struct hemi_gvisor_ring_setup from
// include/uapi/linux/hemi_gvisor.h.
//
// +marshal
type HemiGvisorRingSetup struct {
	_                structs.HostLayout
	ABIVersion       uint32
	Flags            uint32
	Features         uint64
	RingID           uint64
	MmapOffset       uint64
	MmapSize         uint64
	Entries          uint32
	DescriptorOffset uint32
	DescriptorSize   uint32
	DataOffset       uint32
	DataStride       uint32
	MaxBytes         uint32
}

// HemiGvisorRingHeader is the read-only geometry header at the beginning of a
// HEMI ring mapping.
//
// +marshal
type HemiGvisorRingHeader struct {
	_                structs.HostLayout
	Magic            uint64
	ABIVersion       uint32
	HeaderSize       uint32
	RingID           uint64
	Entries          uint32
	DescriptorOffset uint32
	DescriptorSize   uint32
	DataOffset       uint32
	DataStride       uint32
	MaxBytes         uint32
	Features         uint64
	Reserved         uint64
}

const (
	HEMI_GVISOR_RING_OP_READ  = uint16(1)
	HEMI_GVISOR_RING_OP_WRITE = uint16(2)
)

// HemiGvisorRingDescriptor is struct hemi_gvisor_ring_descriptor from
// include/uapi/linux/hemi_gvisor.h.
//
// +marshal
type HemiGvisorRingDescriptor struct {
	_        structs.HostLayout
	Addr     uint64
	Len      uint32
	Op       uint16
	Flags    uint16
	Done     uint32
	Result   int32
	Reserved [5]uint64
}

// HemiGvisorRingEnter is struct hemi_gvisor_ring_enter from
// include/uapi/linux/hemi_gvisor.h.
//
// +marshal
type HemiGvisorRingEnter struct {
	_        structs.HostLayout
	RingID   uint64
	MMHandle uint64
	Count    uint32
	Flags    uint32
	Reserved uint64
}

// HemiGvisorBindMM is struct hemi_gvisor_bind_mm from
// include/uapi/linux/hemi_gvisor.h.
//
// +marshal
type HemiGvisorBindMM struct {
	_        structs.HostLayout
	MMHandle uint64
	Flags    uint32
	PortalFD int32
}

var (
	HEMI_GVISOR_SETUP_RING = IOWR(HEMI_GVISOR_IOCTL_TYPE, 0x15, uint32((*HemiGvisorRingSetup)(nil).SizeBytes()))
	HEMI_GVISOR_ENTER_RING = IOW(HEMI_GVISOR_IOCTL_TYPE, 0x16, uint32((*HemiGvisorRingEnter)(nil).SizeBytes()))
	HEMI_GVISOR_BIND_MM    = IOWR(HEMI_GVISOR_IOCTL_TYPE, 0x17, uint32((*HemiGvisorBindMM)(nil).SizeBytes()))
)

const (
	HEMI_GVISOR_OP_NONE     = 0
	HEMI_GVISOR_OP_MAP_FILE = 1
)
