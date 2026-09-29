package testkit

import (
	"sort"
	"time"

	"github.com/assurrussa/goauth"
)

type emailQuota struct {
	waiting bool
	hourly  bool
	daily   bool
	retryAt time.Time
}

func (q *emailQuota) addRetry(at time.Time) {
	if at.After(q.retryAt) {
		q.retryAt = at
	}
}

func evaluateEmailQuota(events []time.Time, now time.Time, limits goauth.EmailChallengeLimits) emailQuota {
	var result emailQuota
	var last time.Time
	for _, occurredAt := range events {
		if occurredAt.After(last) {
			last = occurredAt
		}
	}
	if !last.IsZero() && limits.MinResendInterval > 0 {
		retryAt := last.Add(limits.MinResendInterval)
		if now.Before(retryAt) {
			result.waiting = true
			result.addRetry(retryAt)
		}
	}
	result.hourly, last = emailWindowRetry(events, now.Add(-time.Hour), limits.PerHour, time.Hour)
	if result.hourly {
		result.addRetry(last)
	}
	result.daily, last = emailWindowRetry(events, now.Add(-24*time.Hour), limits.PerDay, 24*time.Hour)
	if result.daily {
		result.addRetry(last)
	}
	return result
}

func emailWindowRetry(events []time.Time, cutoff time.Time, limit int, window time.Duration) (bool, time.Time) {
	if limit <= 0 {
		return true, time.Time{}
	}
	active := make([]time.Time, 0, len(events))
	for _, occurredAt := range events {
		if !occurredAt.Before(cutoff) {
			active = append(active, occurredAt)
		}
	}
	if len(active) < limit {
		return false, time.Time{}
	}
	// The limit-th newest event is the one that must leave the inclusive window.
	sort.Slice(active, func(i, j int) bool { return active[i].After(active[j]) })
	return true, active[limit-1].Add(window)
}
