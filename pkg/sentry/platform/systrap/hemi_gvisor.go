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
	"runtime"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

const hemiGvisorDevicePath = "/dev/hemi_gvisor"

var hemiGvisorDevice = struct {
	sync.Mutex
	fd       int32
	disabled bool
}{
	fd: -1,
}

func hemiGvisorDeviceFD() (int32, bool) {
	hemiGvisorDevice.Lock()
	defer hemiGvisorDevice.Unlock()

	if hemiGvisorDevice.fd >= 0 {
		return hemiGvisorDevice.fd, true
	}
	if hemiGvisorDevice.disabled {
		return -1, false
	}

	fd, err := unix.Open(hemiGvisorDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		hemiGvisorDevice.disabled = true
		log.Warningf("HEMI gVisor device unavailable: %v", err)
		return -1, false
	}
	hemiGvisorDevice.fd = int32(fd)
	return hemiGvisorDevice.fd, true
}

type hemiGvisorTask interface {
	GetFile(int32) *vfs.FileDescription
}

func (s *subprocess) prepareHemiGvisorMapFile(ctx context.Context, c *platformContext, ac *arch.Context64) {
	if runtime.GOARCH != "amd64" || ac.SyscallNo() != unix.SYS_MMAP {
		return
	}
	args := ac.SyscallArgs()
	prot := args[2].Int()
	flags := args[3].Int()
	if flags&linux.MAP_ANONYMOUS != 0 {
		return
	}
	devFD, ok := hemiGvisorDeviceFD()
	if !ok {
		return
	}
	task, ok := ctx.(hemiGvisorTask)
	if !ok {
		return
	}
	hostFD, hostOffset, err := hemiGvisorLookupHostFile(ctx, task, prot, flags, args)
	if err != nil {
		c.clearHemiGvisorOp()
		log.Warningf("HEMI gVisor MAP_FILE lookup failed, falling back to sentry mmap: %v", err)
		return
	}
	if !c.prepareHemiGvisorMapFile(devFD, int32(hostFD), hostOffset) {
		return
	}
}

func (c *platformContext) prepareHemiGvisorMapFile(devFD, hostFD int32, hostOffset uint64) bool {
	if c.sharedContext == nil {
		return false
	}
	tc := c.sharedContext.shared
	atomic.StoreUint64(&tc.HemiOp, linux.HEMI_GVISOR_OP_NONE)
	atomic.StoreUint64(&tc.HemiDeviceFD, uint64(uint32(devFD)))
	atomic.StoreUint64(&tc.HemiHostFD, uint64(uint32(hostFD)))
	atomic.StoreUint64(&tc.HemiHostOffset, hostOffset)
	atomic.StoreUint64(&tc.HemiOp, linux.HEMI_GVISOR_OP_MAP_FILE)
	return true
}

func (c *platformContext) clearHemiGvisorOp() {
	if c.sharedContext != nil {
		atomic.StoreUint64(&c.sharedContext.shared.HemiOp, linux.HEMI_GVISOR_OP_NONE)
	}
}

func hemiGvisorLookupHostFile(ctx context.Context, task hemiGvisorTask, prot, flags int32, args arch.SyscallArguments) (int, uint64, error) {
	private := flags&linux.MAP_PRIVATE != 0
	shared := flags&linux.MAP_SHARED != 0
	if private == shared {
		return -1, 0, linuxerr.EINVAL
	}

	length, ok := hostarch.Addr(args[1].Uint64()).RoundUp()
	if !ok {
		return -1, 0, linuxerr.ENOMEM
	}
	if length == 0 {
		return -1, 0, linuxerr.EINVAL
	}

	fd := args[4].Int()
	file := task.GetFile(fd)
	if file == nil {
		return -1, 0, linuxerr.EBADF
	}
	defer file.DecRef(ctx)

	if !file.IsReadable() {
		return -1, 0, linuxerr.EACCES
	}

	opts := memmap.MMapOpts{
		Length:   uint64(length),
		Offset:   args[5].Uint64(),
		Addr:     args[0].Pointer(),
		Fixed:    flags&linux.MAP_FIXED != 0,
		Unmap:    flags&linux.MAP_FIXED != 0,
		Map32Bit: flags&linux.MAP_32BIT != 0,
		Private:  private,
		Perms: hostarch.AccessType{
			Read:    linux.PROT_READ&prot != 0,
			Write:   linux.PROT_WRITE&prot != 0,
			Execute: linux.PROT_EXEC&prot != 0,
		},
		MaxPerms:  hostarch.AnyAccess,
		GrowsDown: linux.MAP_GROWSDOWN&flags != 0,
		Stack:     linux.MAP_STACK&flags != 0,
	}
	if linux.MAP_POPULATE&flags != 0 {
		opts.PlatformEffect = memmap.PlatformEffectCommit
	}
	if linux.MAP_LOCKED&flags != 0 {
		opts.MLockMode = memmap.MLockEager
	}
	defer func() {
		if opts.MappingIdentity != nil {
			opts.MappingIdentity.DecRef(ctx)
		}
	}()

	if shared && !file.IsWritable() {
		opts.MaxPerms.Write = false
	}
	if shared {
		if seals, err := tmpfs.GetSeals(file); err == nil && seals&linux.F_SEAL_WRITE != 0 {
			if opts.Perms.Write {
				return -1, 0, linuxerr.EPERM
			}
			opts.MaxPerms.Write = false
		}
	}
	if file.Mount().MountFlags()&linux.ST_NOEXEC != 0 {
		if opts.Perms.Execute {
			return -1, 0, linuxerr.EPERM
		}
		opts.MaxPerms.Execute = false
	}
	if err := file.ConfigureMMap(ctx, &opts); err != nil {
		return -1, 0, err
	}
	return hemiGvisorHostFile(ctx, &opts)
}

func hemiGvisorHostFile(ctx context.Context, opts *memmap.MMapOpts) (int, uint64, error) {
	if opts.Mappable == nil {
		return -1, 0, linuxerr.ENODEV
	}
	end := opts.Offset + opts.Length
	if end < opts.Offset {
		return -1, 0, linuxerr.EOVERFLOW
	}
	mr := memmap.MappableRange{Start: opts.Offset, End: end}

	at := opts.Perms
	if opts.Private {
		at.Read = true
		at.Write = false
	}
	if !at.Any() {
		at.Read = true
	}

	ts, err := opts.Mappable.Translate(ctx, mr, mr, at)
	if len(ts) == 0 {
		if err != nil {
			return -1, 0, err
		}
		return -1, 0, linuxerr.ENODEV
	}
	if ts[0].Source.Start > mr.Start || ts[0].Source.End < mr.End {
		return -1, 0, linuxerr.ENODEV
	}

	hostOffset := ts[0].Offset + (mr.Start - ts[0].Source.Start)
	fr := memmap.FileRange{Start: hostOffset, End: hostOffset + opts.Length}
	ts[0].File.IncRef(fr, pgalloc.MemoryCgroupIDFromContext(ctx))
	defer ts[0].File.DecRef(fr)

	hostFD, err := ts[0].File.DataFD(fr)
	if err != nil {
		return -1, 0, err
	}
	if hostFD < 0 {
		return -1, 0, linuxerr.ENODEV
	}
	return hostFD, hostOffset, nil
}
