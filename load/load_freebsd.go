// +build freebsd

package load

import (
	"os/exec"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/internal/common"
)

func LoadAvg() (*LoadAvgStat, error) {
	values, err := common.DoSysctrl("vm.loadavg")
	if err != nil {
		return nil, err
	}

	load1, err := strconv.ParseFloat(values[0], 64)
	if err != nil {
		return nil, err
	}
	load5, err := strconv.ParseFloat(values[1], 64)
	if err != nil {
		return nil, err
	}
	load15, err := strconv.ParseFloat(values[2], 64)
	if err != nil {
		return nil, err
	}

	ret := &LoadAvgStat{
		Load1:  float64(load1),
		Load5:  float64(load5),
		Load15: float64(load15),
	}

	return ret, nil
}

func Misc() (*MiscStat, error) {
	bin, err := exec.LookPath("ps")
	if err != nil {
		return nil, err
	}
	out, err := invoke.Command(bin, "axo", "state")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(out), "\n")

	ret := MiscStat{}
	for _, l := range lines {
		if strings.Contains(l, "R") {
			ret.ProcsRunning += 1
		} else if strings.Contains(l, "D") {
			ret.ProcsBlocked += 1
		}
	}

	return &ret, nil
}
