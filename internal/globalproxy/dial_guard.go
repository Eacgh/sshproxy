package globalproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	maxConcurrentGlobalDials     = 12
	// 同一目标允许少量并发，对齐 SOCKS5 的多连接行为，避免页面多个资源排队。
	maxConcurrentTargetDials     = 4
	// 冷却只用于避免同一目标短时间内重复堆积建连，不应把慢链路长期拒之门外；
	// 所以从短冷却开始，最多暂停 1 分钟。
	targetTimeoutInitialCooldown = 5 * time.Second
	targetTimeoutMaximumCooldown = time.Minute
)

type targetDialState struct {
	slots           chan struct{}
	blockedUntil    time.Time
	timeoutFailures int
}

// dialGuard 限制尚未建立的 SSH 通道。已建立后的下载连接不会占用名额，
// 因此不会限制正常吞吐；它只阻止不可达目标短时间内并发堆积。
type dialGuard struct {
	global  chan struct{}
	mu      sync.Mutex
	targets map[string]*targetDialState
}

func newDialGuard() *dialGuard {
	return &dialGuard{
		global:  make(chan struct{}, maxConcurrentGlobalDials),
		targets: make(map[string]*targetDialState),
	}
}

func (g *dialGuard) acquire(ctx context.Context, target string) (func(), error) {
	state, err := g.targetState(target)
	if err != nil {
		return nil, err
	}
	select {
	case state.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if remaining := g.cooldownRemaining(state); remaining > 0 {
		<-state.slots
		return nil, targetCoolingDownError{remaining: remaining}
	}
	// 先取得同目标名额，再占全局名额；否则同一域名的大量等待请求会
	// 把全局队列全部占满，反而阻塞其他可以立即建立的网站。
	select {
	case g.global <- struct{}{}:
	case <-ctx.Done():
		<-state.slots
		return nil, ctx.Err()
	}

	return func() {
		<-g.global
		<-state.slots
	}, nil
}

func (g *dialGuard) targetState(target string) (*targetDialState, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	state := g.targets[target]
	if state == nil {
		state = &targetDialState{slots: make(chan struct{}, maxConcurrentTargetDials)}
		g.targets[target] = state
	}
	if remaining := time.Until(state.blockedUntil); remaining > 0 {
		return nil, targetCoolingDownError{remaining: remaining}
	}
	return state, nil
}

func (g *dialGuard) cooldownRemaining(state *targetDialState) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	return time.Until(state.blockedUntil)
}

func (g *dialGuard) record(target string, err error) {
	if err != nil && !isTimeoutFailure(err) {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	state := g.targets[target]
	if state == nil {
		return
	}
	if err == nil {
		state.blockedUntil = time.Time{}
		state.timeoutFailures = 0
		return
	}
	state.timeoutFailures++
	// 5s、10s、20s、40s、60s（16 倍后按上限截断），最多暂停 1 分钟。
	multiplier := 1 << min(state.timeoutFailures-1, 4)
	cooldown := time.Duration(multiplier) * targetTimeoutInitialCooldown
	if cooldown > targetTimeoutMaximumCooldown {
		cooldown = targetTimeoutMaximumCooldown
	}
	blockedUntil := time.Now().Add(cooldown)
	if blockedUntil.After(state.blockedUntil) {
		state.blockedUntil = blockedUntil
	}
}

func isTimeoutFailure(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netError net.Error
	return errors.As(err, &netError) && netError.Timeout()
}

type targetCoolingDownError struct {
	remaining time.Duration
}

func (e targetCoolingDownError) Error() string {
	seconds := max(1, int(e.remaining.Round(time.Second)/time.Second))
	return fmt.Sprintf("目标连接刚刚超时，已暂停重试 %d 秒", seconds)
}
