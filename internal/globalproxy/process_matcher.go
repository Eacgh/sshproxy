package globalproxy

import (
	"path/filepath"
	"strings"
	"sync"

	"sshvpn/internal/config"
)

// ProcessMatcher 维护按进程分流的白名单规则，支持运行期并发读取与热更新。
// 规则支持完整可执行文件路径、目录前缀（以 \ 或 / 结尾）以及进程名，
// 并支持按“自身路径 + 父/祖先进程链”联合匹配，覆盖派生的全部子进程。
type ProcessMatcher struct {
	mu          sync.RWMutex
	exactPaths  map[string]struct{}
	dirPrefixes []string
	baseNames   map[string]struct{}
}

// NewProcessMatcher 根据初始规则创建进程匹配器。
func NewProcessMatcher(rules []config.ProcessRule) *ProcessMatcher {
	matcher := &ProcessMatcher{}
	matcher.SetRules(rules)
	return matcher
}

// SetRules 原子替换当前的进程分流规则列表。
func (m *ProcessMatcher) SetRules(rules []config.ProcessRule) {
	exactPaths := make(map[string]struct{})
	dirSeen := make(map[string]struct{})
	var dirPrefixes []string
	baseNames := make(map[string]struct{})

	for _, rule := range rules {
		if !rule.IsEnabled() {
			continue
		}
		target := strings.TrimSpace(rule.MatchTarget())
		if target == "" {
			continue
		}
		if strings.ContainsAny(target, `\/`) {
			if strings.HasSuffix(target, `\`) || strings.HasSuffix(target, "/") {
				dir := normalizeMatchPath(target)
				if !strings.HasSuffix(dir, `\`) {
					dir += `\`
				}
				if _, exists := dirSeen[dir]; !exists {
					dirSeen[dir] = struct{}{}
					dirPrefixes = append(dirPrefixes, dir)
				}
			} else {
				exactPaths[normalizeMatchPath(target)] = struct{}{}
			}
		} else {
			baseNames[strings.ToLower(target)] = struct{}{}
		}
	}

	m.mu.Lock()
	m.exactPaths = exactPaths
	m.dirPrefixes = dirPrefixes
	m.baseNames = baseNames
	m.mu.Unlock()
}

// HasRules 报告当前是否至少有一条已启用的匹配规则。
func (m *ProcessMatcher) HasRules() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	has := len(m.exactPaths) > 0 || len(m.dirPrefixes) > 0 || len(m.baseNames) > 0
	m.mu.RUnlock()
	return has
}

// Match 判断单个可执行文件路径是否命中任何已启用的白名单规则。
func (m *ProcessMatcher) Match(processPath string) bool {
	_, ok := m.MatchAny([]string{processPath})
	return ok
}

// MatchAny 按顺序检查进程自身路径及祖先进程路径，命中任一规则即返回命中路径。
func (m *ProcessMatcher) MatchAny(paths []string) (string, bool) {
	if m == nil || len(paths) == 0 {
		return "", false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, candidate := range paths {
		if m.matchesSingleLocked(candidate) {
			return candidate, true
		}
	}
	return "", false
}

func (m *ProcessMatcher) matchesSingleLocked(processPath string) bool {
	trimmed := strings.TrimSpace(processPath)
	if trimmed == "" {
		return false
	}
	normalized := normalizeMatchPath(trimmed)
	if _, ok := m.exactPaths[normalized]; ok {
		return true
	}
	for _, prefix := range m.dirPrefixes {
		if strings.HasPrefix(normalized, prefix) {
			return true
		}
	}
	base := extractBaseName(normalized)
	if _, ok := m.baseNames[base]; ok {
		return true
	}
	stem := strings.TrimSuffix(base, ".exe")
	if stem != base {
		if _, ok := m.baseNames[stem]; ok {
			return true
		}
	}
	return false
}

func normalizeMatchPath(path string) string {
	replaced := strings.ReplaceAll(strings.TrimSpace(path), "/", `\`)
	cleaned := filepath.Clean(replaced)
	return strings.ToLower(strings.ReplaceAll(cleaned, "/", `\`))
}

func extractBaseName(normalizedPath string) string {
	index := strings.LastIndexByte(normalizedPath, '\\')
	if index >= 0 {
		return normalizedPath[index+1:]
	}
	return normalizedPath
}
