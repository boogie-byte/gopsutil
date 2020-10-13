package libkvm

/*
#cgo LDFLAGS: -lkvm
#include <limits.h>
#include <kvm.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/sysctl.h>

// This wrapper is needed in order to pass KVM_NO_FILES to
// the kvm_openfiles function. It cannot be done via Cgo since
// C.int type is hardcoded to be 4 bytes long, and KVM_NO_FILES
// overflows it.
kvm_t *
__openfiles(char *errbuf){
    return kvm_openfiles(NULL,NULL,NULL,KVM_NO_FILES,errbuf);
}
*/
import "C"

import (
	"fmt"
	"strings"
	"unsafe"
)

type ProcInfo struct {
	Pid         int32
	Ppid        int32
	Stat        string
	Uid         uint32
	Ruid        uint32
	Gid         uint32
	Rgid        uint32
	Groups      []uint32
	Svuid       uint32
	Svgid       uint32
	Tdev        uint32
	Nice        uint8
	Uru_inblock uint64
	Uru_oublock uint64
	Uutime_sec  uint32
	Uutime_usec uint32
	Ustime_sec  uint32
	Ustime_usec uint32
	Comm        string
	Vm_rssize   int32
	Vm_tsize    int32
	Vm_dsize    int32
	Vm_ssize    int32
}

func GetProcs(arg int32) ([]*ProcInfo, error) {
	// Initialize error message buffer for kvm_openfiles
	errbuf := C.CString(strings.Repeat("\x00", C._POSIX2_LINE_MAX))
	defer C.free(unsafe.Pointer(errbuf))

	// Get kernel descriptor
	kd := C.__openfiles(errbuf)
	if kd == nil {
		return nil, fmt.Errorf(C.GoString(errbuf))
	}
	defer C.kvm_close(kd)

	// Get kproc_info array
	cArg := C.int(arg)
	var cnt C.int // kp length
	kpArray := C.kvm_getprocs(kd, C.KERN_PROC_ALL, cArg, C.sizeof_struct_kinfo_proc, &cnt)
	if kpArray == nil {
		cErrStr := C.kvm_geterr(kd)
		errStr := C.GoString(cErrStr)
		return nil, fmt.Errorf(errStr)
	}

	var res []*ProcInfo
	count := int(cnt)
	for i := 0; i < count; i++ {
		base := uintptr(unsafe.Pointer(kpArray))
		offset := uintptr(C.sizeof_struct_kinfo_proc * i)
		kp := (*C.struct_kinfo_proc)(unsafe.Pointer(base + offset))

		pi := &ProcInfo{
			Pid:         int32(kp.p_pid),
			Ppid:        int32(kp.p_ppid),
			Uid:         uint32(kp.p_uid),
			Ruid:        uint32(kp.p_ruid),
			Gid:         uint32(kp.p_gid),
			Rgid:        uint32(kp.p_rgid),
			Svuid:       uint32(kp.p_svuid),
			Svgid:       uint32(kp.p_svgid),
			Tdev:        uint32(kp.p_tdev),
			Nice:        uint8(kp.p_nice),
			Uru_inblock: uint64(kp.p_uru_inblock),
			Uru_oublock: uint64(kp.p_uru_oublock),
			Uutime_sec:  uint32(kp.p_uutime_sec),
			Uutime_usec: uint32(kp.p_uutime_usec),
			Ustime_sec:  uint32(kp.p_ustime_sec),
			Ustime_usec: uint32(kp.p_ustime_usec),
			Comm:        C.GoString(&kp.p_comm[0]),
			Vm_rssize:   int32(kp.p_vm_rssize),
			Vm_tsize:    int32(kp.p_vm_tsize),
			Vm_dsize:    int32(kp.p_vm_dsize),
			Vm_ssize:    int32(kp.p_vm_ssize),
		}

		for i := 0; i < int(kp.p_ngroups); i++ {
			pi.Groups = append(pi.Groups, uint32(kp.p_groups[i]))
		}

		switch kp.p_stat {
		case C.SIDL:
		case C.SRUN:
		case C.SONPROC:
			pi.Stat = "R"
		case C.SSLEEP:
			pi.Stat = "S"
		case C.SSTOP:
			pi.Stat = "T"
		case C.SDEAD:
			pi.Stat = "Z"
		}

		res = append(res, pi)
	}

	return res, nil
}
