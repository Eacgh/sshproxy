//go:build !windows

package globalproxy

import "net/netip"

// RunningProcess 表示系统中正在运行的进程信息（非 Windows 平台占位定义）。
type RunningProcess struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// ProcessIdentity 表示一次套接字反查得到的进程及其祖先进程路径链。
type ProcessIdentity struct {
	PID   uint32
	Path  string
	Paths []string
}

type processLookup interface {
	LookupTCP(srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) (ProcessIdentity, bool)
	LookupUDP(srcIP netip.Addr, srcPort uint16) (ProcessIdentity, bool)
}

type noopProcessLookup struct{}

func (noopProcessLookup) LookupTCP(netip.Addr, uint16, netip.Addr, uint16) (ProcessIdentity, bool) {
	return ProcessIdentity{}, false
}

func (noopProcessLookup) LookupUDP(netip.Addr, uint16) (ProcessIdentity, bool) {
	return ProcessIdentity{}, false
}

// ListRunningProcesses 在非 Windows 平台返回空列表。
func ListRunningProcesses() ([]RunningProcess, error) {
	return nil, nil
}
