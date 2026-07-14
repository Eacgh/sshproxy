package globalproxy

import (
	"context"
	"errors"
	"testing"
)

func TestDialGuardLimitsOneTarget(t *testing.T) {
	guard := newDialGuard()
	releases := make([]func(), 0, maxConcurrentTargetDials)
	for range maxConcurrentTargetDials {
		release, err := guard.acquire(context.Background(), "example.com:443")
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}
	defer func() {
		for _, release := range releases {
			release()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := guard.acquire(ctx, "example.com:443"); !errors.Is(err, context.Canceled) {
		t.Fatalf("超出同目标并发上限后返回 %v；期望 context.Canceled", err)
	}
}

func TestDialGuardTemporarilyStopsTimedOutTarget(t *testing.T) {
	guard := newDialGuard()
	release, err := guard.acquire(context.Background(), "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	release()
	guard.record("example.com:443", context.DeadlineExceeded)

	_, err = guard.acquire(context.Background(), "example.com:443")
	var cooldown targetCoolingDownError
	if !errors.As(err, &cooldown) {
		t.Fatalf("超时目标没有进入短暂熔断：%v", err)
	}
}
