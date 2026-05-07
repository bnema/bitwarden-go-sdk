package ports

// Random reads random bytes.
type Random interface {
	Read(p []byte) (int, error)
}
