package globalproxy

import (
	"testing"

	"sshvpn/internal/config"
)

func TestProcessMatcherPathAndBasenameRules(t *testing.T) {
	disabled := false
	enabled := true
	matcher := NewProcessMatcher([]config.ProcessRule{
		{
			Name:    "msedge",
			Path:    `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
			Enabled: &enabled,
		},
		{
			Name:    "curl",
			Enabled: &enabled,
		},
		{
			Name:    "firefox",
			Path:    `C:\Program Files\Mozilla Firefox\firefox.exe`,
			Enabled: &disabled,
		},
	})

	if !matcher.HasRules() {
		t.Fatal("HasRules() 应返回 true")
	}
	if !matcher.Match(`c:/Program Files (x86)/Microsoft/Edge/Application/MSEDGE.EXE`) {
		t.Fatal("规范化完整路径应命中 Edge 规则")
	}
	if matcher.Match(`D:\Other\msedge.exe`) {
		t.Fatal("完整路径规则不应误匹配其他目录的同名文件")
	}
	if !matcher.Match(`C:\Windows\System32\curl.exe`) {
		t.Fatal("无路径规则应按进程名匹配 curl.exe")
	}
	if matcher.Match(`C:\Program Files\Mozilla Firefox\firefox.exe`) {
		t.Fatal("已禁用的 Firefox 规则不应命中")
	}

	matcher.SetRules([]config.ProcessRule{{Name: "firefox.exe"}})
	if matcher.Match(`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`) {
		t.Fatal("热更新后旧 Edge 规则不应再命中")
	}
	if !matcher.Match(`C:\Program Files\Mozilla Firefox\firefox.exe`) {
		t.Fatal("热更新后 Firefox 规则应生效")
	}
}

func TestProcessMatcherAncestorChainAndDirectoryPrefix(t *testing.T) {
	matcher := NewProcessMatcher([]config.ProcessRule{
		{
			Name: "Antigravity",
			Path: `C:\Users\11750\AppData\Local\Programs\antigravity\Antigravity.exe`,
		},
		{
			Name: "MyTools",
			Path: `D:\Apps\MyTools\`,
		},
	})

	// 1. 子进程 language_server.exe 通过父进程 Antigravity.exe 命中白名单。
	chain := []string{
		`C:\Users\11750\AppData\Local\Programs\antigravity\resources\bin\language_server.exe`,
		`C:\Users\11750\AppData\Local\Programs\antigravity\Antigravity.exe`,
		`C:\Windows\explorer.exe`,
	}
	hit, ok := matcher.MatchAny(chain)
	if !ok || hit != chain[1] {
		t.Fatalf("MatchAny(chain) = (%q, %v)，期望命中祖先 %q", hit, ok, chain[1])
	}

	// 2. 目录前缀规则应命中目录下任意深度的程序，且不误伤相似前缀目录。
	if !matcher.Match(`d:/Apps/MyTools/sub/worker.exe`) {
		t.Fatal("目录前缀规则应命中子目录程序")
	}
	if matcher.Match(`D:\Apps\MyTools2\worker.exe`) {
		t.Fatal("目录前缀规则不应误匹配兄弟目录 MyTools2")
	}
}
