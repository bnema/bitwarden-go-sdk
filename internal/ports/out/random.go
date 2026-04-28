package out

// Random reads random bytes.
type Random interface {
	Read(p []byte) (int, error)
}
