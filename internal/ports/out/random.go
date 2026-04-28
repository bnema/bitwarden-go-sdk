package out

type Random interface {
	Read(p []byte) (int, error)
}
