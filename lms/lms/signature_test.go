package lms_test

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trailofbits/lms-go/lms/common"
	"github.com/trailofbits/lms-go/lms/lms"
)

func TestSignatureFromBytes(t *testing.T) {
	for i := 0; i < 1000; i++ {
		bytes := make([]byte, i)
		_, err := lms.LmsSignatureFromBytes(bytes)
		assert.Error(t, err)
	}
}

// TestSignatureFromBytes_ShortBufferDoesNotPanic is a regression test for an
// out-of-bounds slice panic in LmsSignatureFromBytes. When the input carries a
// valid LM-OTS typecode but is only long enough to reach, not contain, the LMS
// typecode, the length guard must reject it with an error instead of panicking
// on the b[otsigmax:otsigmax+4] read.
//
// TestSignatureFromBytes above cannot catch this: its all-zero buffers carry an
// invalid LM-OTS typecode (rejected earlier) and never exceed 1000 bytes, which
// is shorter than otsigmax for this parameter set.
func TestSignatureFromBytes_ShortBufferDoesNotPanic(t *testing.T) {
	// A valid LM-OTS typecode so parsing proceeds to the LMS typecode read.
	otssiglen, err := common.LMOTS_SHA256_N32_W8.LmsOtsSigLength()
	assert.NoError(t, err)
	otsigmax := 4 + otssiglen // byte offset of the 4-byte LMS typecode

	// Lengths in [otsigmax-3, otsigmax+3] previously passed the length guard
	// and then read b[otsigmax:otsigmax+4] out of bounds. Every length here
	// must return an error, never panic.
	for l := otsigmax - 4; l <= otsigmax+4; l++ {
		b := make([]byte, int(l))
		binary.BigEndian.PutUint32(b[4:8], uint32(common.LMOTS_SHA256_N32_W8))
		_, err := lms.LmsSignatureFromBytes(b)
		assert.Error(t, err, "len=%d must return an error, not panic", l)
	}
}
