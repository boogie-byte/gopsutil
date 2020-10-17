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

// Helper function for easy array value retrieval
char *
__arr_elem(char **vec, uint offset){
    return *(vec + offset);
}
*/
import "C"

import (
	"fmt"
	"strings"
	"unsafe"
)

type ProcInfo struct {
	Comm        string
	Pid         int32
	Ppid        int32
	Stat        string
	Uid         uint32
	Ruid        uint32
	Svuid       uint32
	Gid         uint32
	Rgid        uint32
	Svgid       uint32
	Groups      []uint32
	Tdev        uint32
	Nice        uint8
	Uru_inblock uint64
	Uru_oublock uint64
	Uutime_sec  uint32
	Uutime_usec uint32
	Ustime_sec  uint32
	Ustime_usec uint32
	Vm_rssize   int32
	Vm_tsize    int32
	Vm_dsize    int32
	Vm_ssize    int32
}

func getKernD() (*C.struct___kvm, error) {
	// Initialize error message buffer for kvm_openfiles
	errbuf := C.CString(strings.Repeat("\x00", C._POSIX2_LINE_MAX))
	defer C.free(unsafe.Pointer(errbuf))

	// Get kernel descriptor
	kd := C.__openfiles(errbuf)
	if kd == nil {
		return nil, fmt.Errorf(C.GoString(errbuf))
	}

	return kd, nil
}

func getProcs(kd *C.struct___kvm, arg int32) (*C.struct_kinfo_proc, int, error) {
	// Get kproc_info array
	cArg := C.int(arg)
	var cnt C.int // kp length
	kp := C.kvm_getprocs(kd, C.KERN_PROC_ALL, cArg, C.sizeof_struct_kinfo_proc, &cnt)
	if kp == nil {
		cErrStr := C.kvm_geterr(kd)
		errStr := C.GoString(cErrStr)
		return nil, 0, fmt.Errorf(errStr)
	}

	return kp, int(cnt), nil
}

func readStrVec(vec **C.char) []string {
	var ret []string

	offset := C.uint(0)
	for {
		strPtr := C.__arr_elem(vec, offset)
		if strPtr == nil {
			break
		}

		str := C.GoString(strPtr)
		ret = append(ret, str)
		offset++
	}

	return ret
}

func GetProcs(arg int32) ([]*ProcInfo, error) {
	kd, err := getKernD()
	if err != nil {
		return nil, err
	}
	defer C.kvm_close(kd)

	kpArray, count, err := getProcs(kd, arg)
	if err != nil {
		return nil, err
	}

	var res []*ProcInfo
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

func GetArgv(arg int32) ([]string, error) {
	kd, err := getKernD()
	if err != nil {
		return nil, err
	}
	defer C.kvm_close(kd)

	kp, _, err := getProcs(kd, arg)
	if err != nil {
		return nil, err
	}

	argv := C.kvm_getargv(kd, kp, 0)
	return readStrVec(argv), nil
}

func GetEnvv(arg int32) ([]string, error) {
	kd, err := getKernD()
	if err != nil {
		return nil, err
	}
	defer C.kvm_close(kd)

	kp, _, err := getProcs(kd, arg)
	if err != nil {
		return nil, err
	}

	argv := C.kvm_getenvv(kd, kp, 0)
	return readStrVec(argv), nil
}
