package lms_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trailofbits/lms-go/lms/lms"
)

func TestSignatureFromBytes(t *testing.T) {
	for i := 0; i < 1000; i++ {
		bytes := make([]byte, i)
		_, err := lms.LmsSignatureFromBytes(bytes)
		assert.Error(t, err)
	}
}
