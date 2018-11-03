package saml

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompressString(t *testing.T) {
	expected := "This is the test string"
	compressed := compressString(expected)
	decompressed := decompressString(compressed)
	assert.Equal(t, expected, decompressed)
	assert.True(t, len(compressed) > len(decompressed))
}

func TestCompress(t *testing.T) {
	expected := []byte("This is the test string")
	compressed := compress(expected)
	decompressed := decompress(compressed)
	assert.Equal(t, expected, decompressed)
	assert.True(t, len(compressed) > len(decompressed))
}
