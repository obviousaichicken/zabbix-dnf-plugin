//nolint:testpackage // cappedBuffer is an internal output-safety primitive.
package command

import (
	"bytes"
	"testing"
)

func TestCappedBuffer(t *testing.T) {
	t.Parallel()

	buffer := newCappedBuffer(5)

	written, err := buffer.Write([]byte("abc"))
	if err != nil {
		t.Fatalf("first Write() error = %v", err)
	}

	if written != 3 {
		t.Fatalf("first Write() = %d, want 3", written)
	}

	written, err = buffer.Write([]byte("defg"))
	if err != nil {
		t.Fatalf("second Write() error = %v", err)
	}

	if written != 4 {
		t.Fatalf("second Write() = %d, want 4", written)
	}

	if !buffer.Overflowed() {
		t.Fatal("Overflowed() = false, want true")
	}

	if got, want := buffer.Bytes(), []byte("abcde"); !bytes.Equal(got, want) {
		t.Fatalf("Bytes() = %q, want %q", got, want)
	}
}

func TestCappedBufferAtLimit(t *testing.T) {
	t.Parallel()

	buffer := newCappedBuffer(5)

	_, err := buffer.Write([]byte("abcde"))
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	if buffer.Overflowed() {
		t.Fatal("Overflowed() = true, want false")
	}
}
