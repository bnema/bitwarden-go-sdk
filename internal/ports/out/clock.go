package out

import "time"

type Clock interface {
	Now() time.Time
}
