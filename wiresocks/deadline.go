package wiresocks

import (
	"context"
	"time"
)

func deadlineFromContext(ctx context.Context) time.Time {
	if ctx == nil {
		return time.Now().Add(time.Second)
	}
	if deadline, ok := ctx.Deadline(); ok {
		return deadline
	}
	return time.Now().Add(time.Second)
}
