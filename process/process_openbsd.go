// +build openbsd

package process

import (
	"C"
	"context"
	"os/exec"

	"strconv"
	"strings"
	"unsafe"

	cpu "github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/internal/common"
	"github.com/shirou/gopsutil/internal/libkvm"
	mem "github.com/shirou/gopsutil/mem"
	net "github.com/shirou/gopsutil/net"
)
import "path/filepath"

// MemoryInfoExStat is different between OSes
type MemoryInfoExStat struct {
}

type MemoryMapsStat struct {
}

func pidsWithContext(ctx context.Context) ([]int32, error) {
	var ret []int32
	procs, err := Processes()
	if err != nil {
		return ret, nil
	}

	for _, p := range procs {
		ret = append(ret, p.Pid)
	}

	return ret, nil
}

func (p *Process) Ppid() (int32, error) {
	return p.PpidWithContext(context.Background())
}

func (p *Process) PpidWithContext(ctx context.Context) (int32, error) {
	k, err := libkvm.GetProcs(p.Pid)
	if err != nil {
		return 0, err
	}

	return k[0].Ppid, nil
}
func (p *Process) Name() (string, error) {
	return p.NameWithContext(context.Background())
}

func (p *Process) NameWithContext(ctx context.Context) (string, error) {
	k, err := libkvm.GetProcs(p.Pid)
	if err != nil {
		return "", err
	}
	name := k[0].Comm

	if len(name) >= 15 {
		cmdlineSlice, err := p.CmdlineSliceWithContext(ctx)
		if err != nil {
			return "", err
		}
		if len(cmdlineSlice) > 0 {
			extendedName := filepath.Base(cmdlineSlice[0])
			if strings.HasPrefix(extendedName, p.name) {
				name = extendedName
			} else {
				name = cmdlineSlice[0]
			}
		}
	}

	return name, nil
}
func (p *Process) Tgid() (int32, error) {
	return 0, common.ErrNotImplementedError
}
func (p *Process) Exe() (string, error) {
	return p.ExeWithContext(context.Background())
}

func (p *Process) ExeWithContext(ctx context.Context) (string, error) {
	return "", common.ErrNotImplementedError
}

func (p *Process) CmdlineSlice() ([]string, error) {
	return p.CmdlineSliceWithContext(context.Background())
}

func (p *Process) CmdlineSliceWithContext(ctx context.Context) ([]string, error) {
	mib := []int32{CTLKern, KernProcArgs, p.Pid, KernProcArgv}
	buf, _, err := common.CallSyscall(mib)

	if err != nil {
		return nil, err
	}

	argc := 0
	argvp := unsafe.Pointer(&buf[0])
	argv := *(**C.char)(unsafe.Pointer(argvp))
	size := unsafe.Sizeof(argv)
	var strParts []string

	for argv != nil {
		strParts = append(strParts, C.GoString(argv))

		argc++
		argv = *(**C.char)(unsafe.Pointer(uintptr(argvp) + uintptr(argc)*size))
	}
	return strParts, nil
}

func (p *Process) Cmdline() (string, error) {
	return p.CmdlineWithContext(context.Background())
}

func (p *Process) CmdlineWithContext(ctx context.Context) (string, error) {
	argv, err := p.CmdlineSlice()
	if err != nil {
		return "", err
	}
	return strings.Join(argv, " "), nil
}

func (p *Process) createTimeWithContext(ctx context.Context) (int64, error) {
	return 0, common.ErrNotImplementedError
}
func (p *Process) Cwd() (string, error) {
	return p.CwdWithContext(context.Background())
}

func (p *Process) CwdWithContext(ctx context.Context) (string, error) {
	return "", common.ErrNotImplementedError
}
func (p *Process) Parent() (*Process, error) {
	return p.ParentWithContext(context.Background())
}

func (p *Process) ParentWithContext(ctx context.Context) (*Process, error) {
	return p, common.ErrNotImplementedError
}
func (p *Process) Status() (string, error) {
	return p.StatusWithContext(context.Background())
}

func (p *Process) StatusWithContext(ctx context.Context) (string, error) {
	k, err := libkvm.GetProcs(p.Pid)
	if err != nil {
		return "", err
	}

	return k[0].Stat, nil
}
func (p *Process) Foreground() (bool, error) {
	return p.ForegroundWithContext(context.Background())
}

func (p *Process) ForegroundWithContext(ctx context.Context) (bool, error) {
	// see https://github.com/shirou/gopsutil/issues/596#issuecomment-432707831 for implementation details
	pid := p.Pid
	ps, err := exec.LookPath("ps")
	if err != nil {
		return false, err
	}
	out, err := invoke.CommandWithContext(ctx, ps, "-o", "stat=", "-p", strconv.Itoa(int(pid)))
	if err != nil {
		return false, err
	}
	return strings.IndexByte(string(out), '+') != -1, nil
}
func (p *Process) Uids() ([]int32, error) {
	return p.UidsWithContext(context.Background())
}

func (p *Process) UidsWithContext(ctx context.Context) ([]int32, error) {
	k, err := libkvm.GetProcs(p.Pid)
	if err != nil {
		return nil, err
	}

	return []int32{int32(k[0].Ruid), int32(k[0].Uid), int32(k[0].Svuid)}, nil
}
func (p *Process) Gids() ([]int32, error) {
	return p.GidsWithContext(context.Background())
}

func (p *Process) GidsWithContext(ctx context.Context) ([]int32, error) {
	k, err := libkvm.GetProcs(p.Pid)
	if err != nil {
		return nil, err
	}

	return []int32{int32(k[0].Rgid), int32(k[0].Gid), int32(k[0].Svgid)}, nil
}
func (p *Process) GroupsWithContext(ctx context.Context) ([]int32, error) {
	k, err := libkvm.GetProcs(p.Pid)
	if err != nil {
		return nil, err
	}

	var groups []int32
	for _, g := range k[0].Groups {
		groups = append(groups, int32(g))
	}

	return groups, nil
}
func (p *Process) Terminal() (string, error) {
	return p.TerminalWithContext(context.Background())
}

func (p *Process) TerminalWithContext(ctx context.Context) (string, error) {
	k, err := libkvm.GetProcs(p.Pid)
	if err != nil {
		return "", err
	}

	termmap, err := getTerminalMap()
	if err != nil {
		return "", err
	}

	return termmap[uint64(k[0].Tdev)], nil
}
func (p *Process) Nice() (int32, error) {
	return p.NiceWithContext(context.Background())
}

func (p *Process) NiceWithContext(ctx context.Context) (int32, error) {
	k, err := libkvm.GetProcs(p.Pid)
	if err != nil {
		return 0, err
	}
	return int32(k[0].Nice), nil
}
func (p *Process) IOnice() (int32, error) {
	return p.IOniceWithContext(context.Background())
}

func (p *Process) IOniceWithContext(ctx context.Context) (int32, error) {
	return 0, common.ErrNotImplementedError
}
func (p *Process) Rlimit() ([]RlimitStat, error) {
	return p.RlimitWithContext(context.Background())
}

func (p *Process) RlimitWithContext(ctx context.Context) ([]RlimitStat, error) {
	var rlimit []RlimitStat
	return rlimit, common.ErrNotImplementedError
}
func (p *Process) RlimitUsage(gatherUsed bool) ([]RlimitStat, error) {
	return p.RlimitUsageWithContext(context.Background(), gatherUsed)
}

func (p *Process) RlimitUsageWithContext(ctx context.Context, gatherUsed bool) ([]RlimitStat, error) {
	var rlimit []RlimitStat
	return rlimit, common.ErrNotImplementedError
}
func (p *Process) IOCounters() (*IOCountersStat, error) {
	return p.IOCountersWithContext(context.Background())
}

func (p *Process) IOCountersWithContext(ctx context.Context) (*IOCountersStat, error) {
	k, err := libkvm.GetProcs(p.Pid)
	if err != nil {
		return nil, err
	}
	return &IOCountersStat{
		ReadCount:  k[0].Uru_inblock,
		WriteCount: k[0].Uru_oublock,
	}, nil
}
func (p *Process) NumCtxSwitches() (*NumCtxSwitchesStat, error) {
	return p.NumCtxSwitchesWithContext(context.Background())
}

func (p *Process) NumCtxSwitchesWithContext(ctx context.Context) (*NumCtxSwitchesStat, error) {
	return nil, common.ErrNotImplementedError
}
func (p *Process) NumFDs() (int32, error) {
	return p.NumFDsWithContext(context.Background())
}

func (p *Process) NumFDsWithContext(ctx context.Context) (int32, error) {
	return 0, common.ErrNotImplementedError
}
func (p *Process) NumThreads() (int32, error) {
	return p.NumThreadsWithContext(context.Background())
}

func (p *Process) NumThreadsWithContext(ctx context.Context) (int32, error) {
	/* not supported, just return 1 */
	return 1, nil
}
func (p *Process) Threads() (map[int32]*cpu.TimesStat, error) {
	return p.ThreadsWithContext(context.Background())
}

func (p *Process) ThreadsWithContext(ctx context.Context) (map[int32]*cpu.TimesStat, error) {
	ret := make(map[int32]*cpu.TimesStat)
	return ret, common.ErrNotImplementedError
}
func (p *Process) Times() (*cpu.TimesStat, error) {
	return p.TimesWithContext(context.Background())
}

func (p *Process) TimesWithContext(ctx context.Context) (*cpu.TimesStat, error) {
	k, err := libkvm.GetProcs(p.Pid)
	if err != nil {
		return nil, err
	}

	return &cpu.TimesStat{
		CPU:    "cpu",
		User:   float64(k[0].Uutime_sec) + float64(k[0].Uutime_usec)/1000000,
		System: float64(k[0].Ustime_sec) + float64(k[0].Ustime_usec)/1000000,
	}, nil
}
func (p *Process) CPUAffinity() ([]int32, error) {
	return p.CPUAffinityWithContext(context.Background())
}

func (p *Process) CPUAffinityWithContext(ctx context.Context) ([]int32, error) {
	return nil, common.ErrNotImplementedError
}
func (p *Process) MemoryInfo() (*MemoryInfoStat, error) {
	return p.MemoryInfoWithContext(context.Background())
}

func (p *Process) MemoryInfoWithContext(ctx context.Context) (*MemoryInfoStat, error) {
	k, err := libkvm.GetProcs(p.Pid)
	if err != nil {
		return nil, err
	}

	pageSize, err := mem.GetPageSize()
	if err != nil {
		return nil, err
	}

	return &MemoryInfoStat{
		RSS: uint64(k[0].Vm_rssize) * pageSize,
		VMS: uint64(k[0].Vm_tsize) + uint64(k[0].Vm_dsize) +
			uint64(k[0].Vm_ssize),
	}, nil
}
func (p *Process) MemoryInfoEx() (*MemoryInfoExStat, error) {
	return p.MemoryInfoExWithContext(context.Background())
}

func (p *Process) MemoryInfoExWithContext(ctx context.Context) (*MemoryInfoExStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) PageFaults() (*PageFaultsStat, error) {
	return p.PageFaultsWithContext(context.Background())
}

func (p *Process) PageFaultsWithContext(ctx context.Context) (*PageFaultsStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) Children() ([]*Process, error) {
	return p.ChildrenWithContext(context.Background())
}

func (p *Process) ChildrenWithContext(ctx context.Context) ([]*Process, error) {
	pids, err := common.CallPgrepWithContext(ctx, invoke, p.Pid)
	if err != nil {
		return nil, err
	}
	ret := make([]*Process, 0, len(pids))
	for _, pid := range pids {
		np, err := NewProcess(pid)
		if err != nil {
			return nil, err
		}
		ret = append(ret, np)
	}
	return ret, nil
}

func (p *Process) OpenFiles() ([]OpenFilesStat, error) {
	return p.OpenFilesWithContext(context.Background())
}

func (p *Process) OpenFilesWithContext(ctx context.Context) ([]OpenFilesStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) Connections() ([]net.ConnectionStat, error) {
	return p.ConnectionsWithContext(context.Background())
}

func (p *Process) ConnectionsWithContext(ctx context.Context) ([]net.ConnectionStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) ConnectionsMax(max int) ([]net.ConnectionStat, error) {
	return p.ConnectionsMaxWithContext(context.Background(), max)
}

func (p *Process) ConnectionsMaxWithContext(ctx context.Context, max int) ([]net.ConnectionStat, error) {
	return []net.ConnectionStat{}, common.ErrNotImplementedError
}

func (p *Process) NetIOCounters(pernic bool) ([]net.IOCountersStat, error) {
	return p.NetIOCountersWithContext(context.Background(), pernic)
}

func (p *Process) NetIOCountersWithContext(ctx context.Context, pernic bool) ([]net.IOCountersStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) MemoryMaps(grouped bool) (*[]MemoryMapsStat, error) {
	return p.MemoryMapsWithContext(context.Background(), grouped)
}

func (p *Process) MemoryMapsWithContext(ctx context.Context, grouped bool) (*[]MemoryMapsStat, error) {
	var ret []MemoryMapsStat
	return &ret, common.ErrNotImplementedError
}

func Processes() ([]*Process, error) {
	return ProcessesWithContext(context.Background())
}

func ProcessesWithContext(ctx context.Context) ([]*Process, error) {
	k, err := libkvm.GetProcs(0)
	if err != nil {
		return nil, err
	}

	var results []*Process
	for _, pi := range k {
		p, err := NewProcess(int32(pi.Pid))
		if err != nil {
			continue
		}

		results = append(results, p)
	}

	return results, nil
}

