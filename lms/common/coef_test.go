package common_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trailofbits/lms-go/lms/common"
)

func TestCoefW1(t *testing.T) {
	s := []byte{0x12, 0x34}
	assert.Equal(t, []uint8{0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0}, common.Coefs(s, common.WINDOW_W1))
}

func TestCoefW2(t *testing.T) {
	s := []byte{0x12, 0x34}
	assert.Equal(t, []uint8{0, 1, 0, 2, 0, 3, 1, 0}, common.Coefs(s, common.WINDOW_W2))
}

func TestCoefW4(t *testing.T) {
	s := []byte{0x12, 0x34}
	assert.Equal(t, []uint8{1, 2, 3, 4}, common.Coefs(s, common.WINDOW_W4))
}

func TestCoefW8(t *testing.T) {
	s := []byte{0x12, 0x34}
	assert.Equal(t, []uint8{0x12, 0x34}, common.Coefs(s, common.WINDOW_W8))
}
