package license

import "time"

const (
	clockRollbackTolerance = 5 * time.Minute
	wallPersistInterval    = 5 * time.Minute
)

func estimatedNow(localNow, lastServerTime, lastWallTime time.Time) (time.Time, bool) {
	localNow = localNow.UTC()
	rollback := !lastWallTime.IsZero() && localNow.Before(lastWallTime.Add(-clockRollbackTolerance))
	estimate := localNow
	if lastServerTime.After(estimate) {
		estimate = lastServerTime
	}
	if lastWallTime.After(estimate) {
		estimate = lastWallTime
	}
	return estimate.UTC(), rollback
}

func shouldPersistWall(now, last time.Time) bool {
	return last.IsZero() || !now.Before(last.Add(wallPersistInterval))
}

func minTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}

func daysRemaining(now, end time.Time) int {
	if !now.Before(end) {
		return 0
	}
	remaining := end.Sub(now)
	days := int(remaining / (24 * time.Hour))
	if remaining%(24*time.Hour) != 0 {
		days++
	}
	return days
}
