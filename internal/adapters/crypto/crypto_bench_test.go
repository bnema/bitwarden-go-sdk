package crypto

import (
	"bytes"
	"context"
	"io"
	"testing"
)

func BenchmarkAttachmentEncrypt1MiB(b *testing.B) {
	eng := NewEngine()
	key := testAttachmentKey64()
	plaintext := bytes.Repeat([]byte("a"), 1024*1024)
	b.SetBytes(int64(len(plaintext)))
	b.ReportAllocs()

	for range b.N {
		var dst bytes.Buffer
		if err := eng.EncryptAttachment(context.Background(), key, bytes.NewReader(plaintext), &dst); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAttachmentDecrypt1MiB(b *testing.B) {
	eng := NewEngine()
	key := testAttachmentKey64()
	plaintext := bytes.Repeat([]byte("a"), 1024*1024)
	var encrypted bytes.Buffer
	if err := eng.EncryptAttachment(context.Background(), key, bytes.NewReader(plaintext), &encrypted); err != nil {
		b.Fatal(err)
	}
	ciphertext := encrypted.Bytes()
	b.SetBytes(int64(len(plaintext)))
	b.ReportAllocs()

	for range b.N {
		if err := eng.DecryptAttachment(context.Background(), key, bytes.NewReader(ciphertext), io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}
