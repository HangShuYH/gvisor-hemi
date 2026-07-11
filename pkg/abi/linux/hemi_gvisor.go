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

// HemiGvisorUserMem is struct hemi_gvisor_user_mem from
// include/uapi/linux/hemi_gvisor.h.
//
// +marshal
type HemiGvisorUserMem struct {
	_          structs.HostLayout
	Addr       uint64
	Len        uint64
	UserBuf    uint64
	TargetTGID int32
	Flags      uint32
}

var (
	HEMI_GVISOR_READ_USER  = IOWR(HEMI_GVISOR_IOCTL_TYPE, 0x11, uint32((*HemiGvisorUserMem)(nil).SizeBytes()))
	HEMI_GVISOR_WRITE_USER = IOWR(HEMI_GVISOR_IOCTL_TYPE, 0x12, uint32((*HemiGvisorUserMem)(nil).SizeBytes()))
)

const (
	HEMI_GVISOR_OP_NONE     = 0
	HEMI_GVISOR_OP_MAP_FILE = 1
)
