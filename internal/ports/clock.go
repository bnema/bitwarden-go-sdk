package ports

import "time"

// Clock provides the current time.
type Clock interface {
	Now() time.Time
}
