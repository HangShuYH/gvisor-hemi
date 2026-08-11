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
	HEMI_USERSPACE_IOCTL_TYPE = uint32('H')

	HEMI_USERSPACE_VMAR_START = uint64(0x0000610000000000)
	HEMI_USERSPACE_VMAR_END   = uint64(0x0000620000000000)
)

// HemiUserspaceAllocMM is struct hemi_userspace_alloc_mm.
//
// +marshal
type HemiUserspaceAllocMM struct {
	_              structs.HostLayout
	MMID           uint64
	TargetTGID     int32
	TargetDeviceFD int32
}

// HemiUserspaceForkMM is struct hemi_userspace_fork_mm.
//
// +marshal
type HemiUserspaceForkMM struct {
	_              structs.HostLayout
	ParentMMID     uint64
	ChildMMID      uint64
	TargetTGID     int32
	TargetDeviceFD int32
}

// HemiUserspaceFreeMM is struct hemi_userspace_free_mm.
//
// +marshal
type HemiUserspaceFreeMM struct {
	_    structs.HostLayout
	MMID uint64
}

var (
	HEMI_USERSPACE_ALLOC_MM = IOW(HEMI_USERSPACE_IOCTL_TYPE, 0x02, uint32((*HemiUserspaceAllocMM)(nil).SizeBytes()))
	HEMI_USERSPACE_FORK_MM  = IOW(HEMI_USERSPACE_IOCTL_TYPE, 0x03, uint32((*HemiUserspaceForkMM)(nil).SizeBytes()))
	HEMI_USERSPACE_FREE_MM  = IOW(HEMI_USERSPACE_IOCTL_TYPE, 0x04, uint32((*HemiUserspaceFreeMM)(nil).SizeBytes()))
)

const (
	HEMI_USERSPACE_ACCESS_READ               = uint32(1)
	HEMI_USERSPACE_ACCESS_WRITE              = uint32(2)
	HEMI_USERSPACE_ACCESS_NOFAULT            = uint32(4)
	HEMI_USERSPACE_ACCESS_IGNORE_PERMISSIONS = uint32(8)

	HEMI_USERSPACE_PF_IGNORE_PERMISSIONS = uint64(1) << 63
)

// HemiUserspaceAccess is struct hemi_userspace_access.
//
// +marshal
type HemiUserspaceAccess struct {
	_       structs.HostLayout
	MMID    uint64
	Addr    uint64
	UserBuf uint64
	Len     uint64
	Done    uint64
	Result  int32
	Access  uint32
}

var HEMI_USERSPACE_ACCESS = IOWR(HEMI_USERSPACE_IOCTL_TYPE, 0x05, uint32((*HemiUserspaceAccess)(nil).SizeBytes()))

const (
	HEMI_USERSPACE_ATOMIC_U32_LOAD    = uint32(0)
	HEMI_USERSPACE_ATOMIC_U32_SWAP    = uint32(1)
	HEMI_USERSPACE_ATOMIC_U32_CMPXCHG = uint32(2)
	HEMI_USERSPACE_ATOMIC_U32_ADD     = uint32(3)
	HEMI_USERSPACE_ATOMIC_U32_OR      = uint32(4)
	HEMI_USERSPACE_ATOMIC_U32_AND     = uint32(5)
	HEMI_USERSPACE_ATOMIC_U32_XOR     = uint32(6)

	HEMI_USERSPACE_ATOMIC_U32_NOFAULT = uint32(1)
)

// HemiUserspaceAtomicU32 is struct hemi_userspace_atomic_u32.
//
// +marshal
type HemiUserspaceAtomicU32 struct {
	_        structs.HostLayout
	MMID     uint64
	Addr     uint64
	Op       uint32
	Old      uint32
	New      uint32
	Value    uint32
	Flags    uint32
	Reserved uint32
}

var HEMI_USERSPACE_ATOMIC_U32 = IOWR(HEMI_USERSPACE_IOCTL_TYPE, 0x06, uint32((*HemiUserspaceAtomicU32)(nil).SizeBytes()))

// HemiUserspaceProbeUser is struct hemi_userspace_probe_user.
//
// +marshal
type HemiUserspaceProbeUser struct {
	_      structs.HostLayout
	MMID   uint64
	Addr   uint64
	Len    uint64
	Done   uint64
	Result int32
	Access uint32
}

var HEMI_USERSPACE_PROBE_USER = IOWR(HEMI_USERSPACE_IOCTL_TYPE, 0x07, uint32((*HemiUserspaceProbeUser)(nil).SizeBytes()))

const (
	HEMI_USERSPACE_RING_ENTRIES           = 8
	HEMI_USERSPACE_RING_DESCRIPTOR_OFFSET = 0
	HEMI_USERSPACE_RING_DESCRIPTOR_SIZE   = 64
	HEMI_USERSPACE_RING_DATA_OFFSET       = 4096
	HEMI_USERSPACE_RING_DATA_STRIDE       = 64 * 1024
	HEMI_USERSPACE_RING_MAX_BYTES         = HEMI_USERSPACE_RING_ENTRIES * HEMI_USERSPACE_RING_DATA_STRIDE
	HEMI_USERSPACE_RING_MMAP_SIZE         = HEMI_USERSPACE_RING_DATA_OFFSET + HEMI_USERSPACE_RING_MAX_BYTES

	HEMI_USERSPACE_RING_OP_READ  = uint16(HEMI_USERSPACE_ACCESS_READ)
	HEMI_USERSPACE_RING_OP_WRITE = uint16(HEMI_USERSPACE_ACCESS_WRITE)
)

// HemiUserspaceRingDescriptor is struct hemi_userspace_ring_descriptor.
//
// +marshal
type HemiUserspaceRingDescriptor struct {
	_        structs.HostLayout
	Addr     uint64
	Len      uint32
	Op       uint16
	Flags    uint16
	Done     uint32
	Result   int32
	Reserved [5]uint64
}

// HemiUserspaceRingSetup is struct hemi_userspace_ring_setup.
//
// +marshal
type HemiUserspaceRingSetup struct {
	_          structs.HostLayout
	RingID     uint64
	MmapOffset uint64
}

// HemiUserspaceRingEnter is struct hemi_userspace_ring_enter.
//
// +marshal
type HemiUserspaceRingEnter struct {
	_        structs.HostLayout
	RingID   uint64
	MMID     uint64
	Count    uint32
	Reserved uint32
}

var (
	HEMI_USERSPACE_SETUP_RING = IOR(HEMI_USERSPACE_IOCTL_TYPE, 0x08, uint32((*HemiUserspaceRingSetup)(nil).SizeBytes()))
	HEMI_USERSPACE_ENTER_RING = IOW(HEMI_USERSPACE_IOCTL_TYPE, 0x09, uint32((*HemiUserspaceRingEnter)(nil).SizeBytes()))
)

const (
	HEMI_USERSPACE_MAP_GUEST_HANDLE = uint32(0)
	HEMI_USERSPACE_MAP_HANDLED      = uint32(1)
)

// HemiUserspaceMapFile is struct hemi_userspace_map_file.
//
// +marshal
type HemiUserspaceMapFile struct {
	_              structs.HostLayout
	MMID           uint64
	Args           [6]uint64
	FileToken      uint64
	InodeToken     uint64
	Result         int64
	TargetTGID     int32
	TargetDeviceFD int32
	Action         uint32
	Reserved       uint32
}

var HEMI_USERSPACE_MAP_FILE = IOWR(HEMI_USERSPACE_IOCTL_TYPE, 0x0a, uint32((*HemiUserspaceMapFile)(nil).SizeBytes()))

const (
	HEMI_USERSPACE_FILE_FAULT_MAX_PAGES = 16

	HEMI_USERSPACE_FILE_FAULT_QUERY    = uint32(0)
	HEMI_USERSPACE_FILE_FAULT_COMPLETE = uint32(1)

	HEMI_USERSPACE_FILE_FAULT_GUEST_HANDLE  = uint32(0)
	HEMI_USERSPACE_FILE_FAULT_HANDLED       = uint32(1)
	HEMI_USERSPACE_FILE_FAULT_GET_FILE_PAGE = uint32(2)

	HEMI_USERSPACE_FILE_PAGES_GUEST   = uint32(0)
	HEMI_USERSPACE_FILE_PAGES_HOST_FD = uint32(1)
)

// HemiUserspaceFilePage is struct hemi_userspace_file_page.
//
// +marshal
type HemiUserspaceFilePage struct {
	_          structs.HostLayout
	HostFD     int64
	HostOffset uint64
}

// HemiUserspaceFileFault is struct hemi_userspace_file_fault.
//
// +marshal
type HemiUserspaceFileFault struct {
	_              structs.HostLayout
	MMID           uint64
	Addr           uint64
	ErrorCode      uint64
	FileToken      uint64
	Offset         uint64
	NumPages       uint32
	Phase          uint32
	Action         uint32
	PageSource     uint32
	TargetTGID     int32
	TargetDeviceFD int32
	Pages          [HEMI_USERSPACE_FILE_FAULT_MAX_PAGES]HemiUserspaceFilePage
}

var HEMI_USERSPACE_FILE_FAULT = IOWR(HEMI_USERSPACE_IOCTL_TYPE, 0x0b, uint32((*HemiUserspaceFileFault)(nil).SizeBytes()))

const (
	HEMI_USERSPACE_RELEASE_PAGE  = uint32(1)
	HEMI_USERSPACE_RELEASE_FILE  = uint32(2)
	HEMI_USERSPACE_RELEASE_INODE = uint32(3)

	HEMI_USERSPACE_RELEASE_RING_ENTRIES = 64
	HEMI_USERSPACE_RELEASE_QUEUE_STRIDE = 2048
)

// HemiUserspaceReleaseRecord is struct hemi_userspace_release_record.
//
// +marshal
type HemiUserspaceReleaseRecord struct {
	_        structs.HostLayout
	Token    uint64
	Count    uint64
	Type     uint32
	Reserved uint32
}

// HemiUserspaceReleaseRing is struct hemi_userspace_release_ring.
//
// +marshal
type HemiUserspaceReleaseRing struct {
	_            structs.HostLayout
	Head         uint32
	HeadReserved [15]uint32
	Tail         uint32
	TailReserved [15]uint32
	Records      [HEMI_USERSPACE_RELEASE_RING_ENTRIES]HemiUserspaceReleaseRecord
}

// HemiUserspaceReleaseSetup is struct hemi_userspace_release_setup.
//
// +marshal
type HemiUserspaceReleaseSetup struct {
	_           structs.HostLayout
	MmapOffset  uint64
	MmapSize    uint64
	QueueCount  uint32
	QueueStride uint32
}

var HEMI_USERSPACE_SETUP_RELEASES = IOR(HEMI_USERSPACE_IOCTL_TYPE, 0x0c, uint32((*HemiUserspaceReleaseSetup)(nil).SizeBytes()))
