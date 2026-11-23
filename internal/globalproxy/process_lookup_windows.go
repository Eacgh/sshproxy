//go:build windows

package globalproxy

import (
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	tcpTableOwnerPIDAll  = 5
	udpTableOwnerPID     = 1
	mibTCPStateListen    = 2
	pidCacheTTL          = 5 * time.Second
	maxAncestorDepth     = 8
	processBasicInfo     = 0
	errorNotEnoughBuffer = uintptr(windows.ERROR_INSUFFICIENT_BUFFER)
)

var (
	iphlpapiDLL                   = windows.NewLazySystemDLL("iphlpapi.dll")
	ntdllDLL                      = windows.NewLazySystemDLL("ntdll.dll")
	procGetExtendedTCPTable       = iphlpapiDLL.NewProc("GetExtendedTcpTable")
	procGetExtendedUDPTable       = iphlpapiDLL.NewProc("GetExtendedUdpTable")
	procNtQueryInformationProcess = ntdllDLL.NewProc("NtQueryInformationProcess")
)

type processBasicInformation struct {
	ExitStatus                   int32
	_                            uint32
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 int32
	_                            uint32
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
}

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

type mibTCP6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPid     uint32
}

type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

type mibUDP6RowOwnerPID struct {
	LocalAddr    [16]byte
	LocalScopeID uint32
	LocalPort    uint32
	OwningPid    uint32
}

// RunningProcess 表示当前系统中正在运行的可选进程条目，供 GUI 选择添加。
type RunningProcess struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// ProcessIdentity 表示一次套接字反查得到的进程及其祖先进程路径链。
// Paths[0] 为套接字所属进程本身路径，Paths[1:] 为沿父进程链向上的祖先路径。
type ProcessIdentity struct {
	PID   uint32
	Path  string
	Paths []string
}

type processLookup interface {
	LookupTCP(srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) (ProcessIdentity, bool)
	LookupUDP(srcIP netip.Addr, srcPort uint16) (ProcessIdentity, bool)
}

type pidInfoEntry struct {
	path       string
	parentPID  uint32
	createTime uint64
	expiresAt  time.Time
}

type windowsProcessLookup struct {
	mu      sync.Mutex
	pidInfo map[uint32]pidInfoEntry
}

func newWindowsProcessLookup() *windowsProcessLookup {
	return &windowsProcessLookup{
		pidInfo: make(map[uint32]pidInfoEntry),
	}
}

func (l *windowsProcessLookup) LookupTCP(srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) (ProcessIdentity, bool) {
	srcIP = srcIP.Unmap()
	dstIP = dstIP.Unmap()

	var pid uint32
	var found bool
	if srcIP.Is4() {
		pid, found = lookupTCPv4(srcIP, srcPort, dstIP, dstPort)
		if !found {
			pid, found = lookupTCPv6(srcIP, srcPort, dstIP, dstPort)
		}
	} else {
		pid, found = lookupTCPv6(srcIP, srcPort, dstIP, dstPort)
	}
	if !found || pid == 0 {
		return ProcessIdentity{}, false
	}
	return l.resolveIdentity(pid)
}

func (l *windowsProcessLookup) LookupUDP(srcIP netip.Addr, srcPort uint16) (ProcessIdentity, bool) {
	srcIP = srcIP.Unmap()

	var pid uint32
	var found bool
	if srcIP.Is4() {
		pid, found = lookupUDPv4(srcIP, srcPort)
		if !found {
			pid, found = lookupUDPv6(srcIP, srcPort)
		}
	} else {
		pid, found = lookupUDPv6(srcIP, srcPort)
	}
	if !found || pid == 0 {
		return ProcessIdentity{}, false
	}
	return l.resolveIdentity(pid)
}

func (l *windowsProcessLookup) resolveIdentity(pid uint32) (ProcessIdentity, bool) {
	info := l.getPIDInfo(pid)
	if info.path == "" {
		return ProcessIdentity{}, false
	}

	paths := make([]string, 0, maxAncestorDepth+1)
	paths = append(paths, info.path)

	visited := map[uint32]struct{}{pid: {}}
	childCreateTime := info.createTime
	parentPID := info.parentPID

	for depth := 0; depth < maxAncestorDepth && parentPID > 4; depth++ {
		if _, seen := visited[parentPID]; seen {
			break
		}
		visited[parentPID] = struct{}{}

		parentInfo := l.getPIDInfo(parentPID)
		if parentInfo.path == "" {
			break
		}
		// 校验父进程创建时间不晚于子进程，防止 PID 复用造成错误归因。
		if parentInfo.createTime != 0 && childCreateTime != 0 && parentInfo.createTime > childCreateTime {
			break
		}
		paths = append(paths, parentInfo.path)
		childCreateTime = parentInfo.createTime
		parentPID = parentInfo.parentPID
	}

	return ProcessIdentity{
		PID:   pid,
		Path:  info.path,
		Paths: paths,
	}, true
}

func (l *windowsProcessLookup) getPIDInfo(pid uint32) pidInfoEntry {
	now := time.Now()
	l.mu.Lock()
	if entry, ok := l.pidInfo[pid]; ok && now.Before(entry.expiresAt) {
		l.mu.Unlock()
		return entry
	}
	l.mu.Unlock()

	entry := queryProcessInfo(pid)
	entry.expiresAt = now.Add(pidCacheTTL)

	l.mu.Lock()
	if len(l.pidInfo) > 1024 {
		for k, v := range l.pidInfo {
			if !now.Before(v.expiresAt) {
				delete(l.pidInfo, k)
			}
		}
	}
	l.pidInfo[pid] = entry
	l.mu.Unlock()
	return entry
}

func lookupTCPv4(srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) (uint32, bool) {
	buf, count, ok := readExtendedTable(procGetExtendedTCPTable, windows.AF_INET, tcpTableOwnerPIDAll)
	if !ok || count == 0 {
		return 0, false
	}
	rowSize := unsafe.Sizeof(mibTCPRowOwnerPID{})
	if len(buf) < 4+int(count)*int(rowSize) {
		return 0, false
	}
	rows := unsafe.Slice((*mibTCPRowOwnerPID)(unsafe.Pointer(&buf[4])), count)
	var fallbackPID uint32
	for _, row := range rows {
		if row.State == mibTCPStateListen {
			continue
		}
		if winPort(row.LocalPort) != srcPort || winPort(row.RemotePort) != dstPort {
			continue
		}
		localAddr := winIPv4(row.LocalAddr)
		remoteAddr := winIPv4(row.RemoteAddr)
		if localAddr == srcIP && remoteAddr == dstIP {
			return row.OwningPid, true
		}
		if fallbackPID == 0 {
			fallbackPID = row.OwningPid
		}
	}
	return fallbackPID, fallbackPID != 0
}

func lookupTCPv6(srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) (uint32, bool) {
	buf, count, ok := readExtendedTable(procGetExtendedTCPTable, windows.AF_INET6, tcpTableOwnerPIDAll)
	if !ok || count == 0 {
		return 0, false
	}
	rowSize := unsafe.Sizeof(mibTCP6RowOwnerPID{})
	if len(buf) < 4+int(count)*int(rowSize) {
		return 0, false
	}
	rows := unsafe.Slice((*mibTCP6RowOwnerPID)(unsafe.Pointer(&buf[4])), count)
	var fallbackPID uint32
	for _, row := range rows {
		if row.State == mibTCPStateListen {
			continue
		}
		if winPort(row.LocalPort) != srcPort || winPort(row.RemotePort) != dstPort {
			continue
		}
		localAddr := netip.AddrFrom16(row.LocalAddr).Unmap()
		remoteAddr := netip.AddrFrom16(row.RemoteAddr).Unmap()
		if localAddr == srcIP && remoteAddr == dstIP {
			return row.OwningPid, true
		}
		if fallbackPID == 0 {
			fallbackPID = row.OwningPid
		}
	}
	return fallbackPID, fallbackPID != 0
}

func lookupUDPv4(srcIP netip.Addr, srcPort uint16) (uint32, bool) {
	buf, count, ok := readExtendedTable(procGetExtendedUDPTable, windows.AF_INET, udpTableOwnerPID)
	if !ok || count == 0 {
		return 0, false
	}
	rowSize := unsafe.Sizeof(mibUDPRowOwnerPID{})
	if len(buf) < 4+int(count)*int(rowSize) {
		return 0, false
	}
	rows := unsafe.Slice((*mibUDPRowOwnerPID)(unsafe.Pointer(&buf[4])), count)
	var wildcardPID uint32
	var portOnlyPID uint32
	for _, row := range rows {
		if winPort(row.LocalPort) != srcPort {
			continue
		}
		localAddr := winIPv4(row.LocalAddr)
		if localAddr == srcIP {
			return row.OwningPid, true
		}
		if localAddr.IsUnspecified() && wildcardPID == 0 {
			wildcardPID = row.OwningPid
		}
		if portOnlyPID == 0 {
			portOnlyPID = row.OwningPid
		}
	}
	if wildcardPID != 0 {
		return wildcardPID, true
	}
	return portOnlyPID, portOnlyPID != 0
}

func lookupUDPv6(srcIP netip.Addr, srcPort uint16) (uint32, bool) {
	buf, count, ok := readExtendedTable(procGetExtendedUDPTable, windows.AF_INET6, udpTableOwnerPID)
	if !ok || count == 0 {
		return 0, false
	}
	rowSize := unsafe.Sizeof(mibUDP6RowOwnerPID{})
	if len(buf) < 4+int(count)*int(rowSize) {
		return 0, false
	}
	rows := unsafe.Slice((*mibUDP6RowOwnerPID)(unsafe.Pointer(&buf[4])), count)
	var wildcardPID uint32
	var portOnlyPID uint32
	for _, row := range rows {
		if winPort(row.LocalPort) != srcPort {
			continue
		}
		localAddr := netip.AddrFrom16(row.LocalAddr).Unmap()
		if localAddr == srcIP {
			return row.OwningPid, true
		}
		if localAddr.IsUnspecified() && wildcardPID == 0 {
			wildcardPID = row.OwningPid
		}
		if portOnlyPID == 0 {
			portOnlyPID = row.OwningPid
		}
	}
	if wildcardPID != 0 {
		return wildcardPID, true
	}
	return portOnlyPID, portOnlyPID != 0
}

func readExtendedTable(proc *windows.LazyProc, af uint32, tableClass uint32) ([]byte, uint32, bool) {
	size := uint32(16 * 1024)
	for range 4 {
		buf := make([]byte, size)
		ret, _, _ := proc.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
			uintptr(af),
			uintptr(tableClass),
			0,
		)
		if ret == 0 {
			if len(buf) < 4 {
				return nil, 0, false
			}
			count := *(*uint32)(unsafe.Pointer(&buf[0]))
			return buf, count, true
		}
		if ret != errorNotEnoughBuffer || size < 4 {
			return nil, 0, false
		}
	}
	return nil, 0, false
}

func winPort(raw uint32) uint16 {
	return uint16((raw&0xFF)<<8 | (raw>>8)&0xFF)
}

func winIPv4(raw uint32) netip.Addr {
	bytes := *(*[4]byte)(unsafe.Pointer(&raw))
	return netip.AddrFrom4(bytes)
}

func queryProcessInfo(pid uint32) pidInfoEntry {
	if pid == 0 || pid == 4 {
		return pidInfoEntry{}
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return pidInfoEntry{}
	}
	defer windows.CloseHandle(handle)

	buf := make([]uint16, 4096)
	size := uint32(len(buf))
	var path string
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err == nil && size > 0 {
		path = windows.UTF16ToString(buf[:size])
	}

	var parentPID uint32
	var pbi processBasicInformation
	var retLen uint32
	status, _, _ := procNtQueryInformationProcess.Call(
		uintptr(handle),
		processBasicInfo,
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if status == 0 {
		parentPID = uint32(pbi.InheritedFromUniqueProcessID)
	}

	var createFT, exitFT, kernelFT, userFT windows.Filetime
	var createTime uint64
	if err := windows.GetProcessTimes(handle, &createFT, &exitFT, &kernelFT, &userFT); err == nil {
		createTime = uint64(createFT.HighDateTime)<<32 | uint64(createFT.LowDateTime)
	}

	return pidInfoEntry{
		path:       path,
		parentPID:  parentPID,
		createTime: createTime,
	}
}

func queryProcessPath(pid uint32) string {
	if pid == 0 || pid == 4 {
		return ""
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(handle)

	buf := make([]uint16, 4096)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil || size == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

// ListRunningProcesses 枚举当前正在运行的用户态进程，去重后按名称排序返回，供 GUI 选择。
func ListRunningProcesses() ([]RunningProcess, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	selfPID := uint32(os.Getpid())
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	seen := make(map[string]struct{})
	var list []RunningProcess
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil, err
	}
	for {
		if entry.ProcessID != 0 && entry.ProcessID != 4 && entry.ProcessID != selfPID {
			if path := queryProcessPath(entry.ProcessID); path != "" {
				key := normalizeMatchPath(path)
				if _, ok := seen[key]; !ok {
					seen[key] = struct{}{}
					base := filepath.Base(path)
					name := strings.TrimSuffix(base, filepath.Ext(base))
					if name == "" {
						name = base
					}
					list = append(list, RunningProcess{
						Name: name,
						Path: path,
					})
				}
			}
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}

	sort.Slice(list, func(i, j int) bool {
		li, lj := strings.ToLower(list[i].Name), strings.ToLower(list[j].Name)
		if li != lj {
			return li < lj
		}
		return strings.ToLower(list[i].Path) < strings.ToLower(list[j].Path)
	})
	return list, nil
}
