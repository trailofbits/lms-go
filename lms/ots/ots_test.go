package ots_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trailofbits/lms-go/lms/common"
	"github.com/trailofbits/lms-go/lms/ots"
)

func TestOtsSignVerify(t *testing.T) {
	for _, tc := range []struct {
		name     string
		typecode uint32
	}{
		{
			name:     "LMOTS_SHA256_N32_W1",
			typecode: common.LMOTS_SHA256_N32_W1.ToUint32(),
		},
		{
			name:     "LMOTS_SHA256_N32_W2",
			typecode: common.LMOTS_SHA256_N32_W2.ToUint32(),
		},
		{
			name:     "LMOTS_SHA256_N32_W4",
			typecode: common.LMOTS_SHA256_N32_W4.ToUint32(),
		},
		{
			name:     "LMOTS_SHA256_N32_W8",
			typecode: common.LMOTS_SHA256_N32_W8.ToUint32(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var err error

			id, err := hex.DecodeString("d08fabd4a2091ff0a8cb4ed834e74534")
			if err != nil {
				panic(err)
			}

			ots_priv, err := ots.NewPrivateKey(common.Uint32ToLmotsType(tc.typecode), 0, common.ID(id))
			if err != nil {
				panic(err)
			}

			ots_pub, err := ots_priv.Public()
			if err != nil {
				panic(err)
			}
			ots_sig, err := ots_priv.Sign([]byte("example"), nil)
			if err != nil {
				panic(err)
			}

			result := ots_pub.Verify([]byte("example"), ots_sig)
			assert.True(t, result)
		})
	}
}

func TestOtsSignVerifyFail(t *testing.T) {
	for _, tc := range []struct {
		name     string
		typecode uint32
	}{
		{
			name:     "LMOTS_SHA256_N32_W1",
			typecode: common.LMOTS_SHA256_N32_W1.ToUint32(),
		},
		{
			name:     "LMOTS_SHA256_N32_W2",
			typecode: common.LMOTS_SHA256_N32_W2.ToUint32(),
		},
		{
			name:     "LMOTS_SHA256_N32_W4",
			typecode: common.LMOTS_SHA256_N32_W4.ToUint32(),
		},
		{
			name:     "LMOTS_SHA256_N32_W8",
			typecode: common.LMOTS_SHA256_N32_W8.ToUint32(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var err error

			id, err := hex.DecodeString("d08fabd4a2091ff0a8cb4ed834e74534")
			if err != nil {
				panic(err)
			}

			ots_priv, err := ots.NewPrivateKey(common.Uint32ToLmotsType(tc.typecode), 0, common.ID(id))
			if err != nil {
				panic(err)
			}

			ots_pub, err := ots_priv.Public()
			if err != nil {
				panic(err)
			}
			ots_sig, err := ots_priv.Sign([]byte("example"), nil)
			if err != nil {
				panic(err)
			}

			// modify q so that the verification fails
			ots_pub_bytes := ots_pub.ToBytes()
			ots_pub_bytes[23] = 1
			ots_pub, err = ots.LmsOtsPublicKeyFromBytes(ots_pub_bytes)
			if err != nil {
				panic(err)
			}
			result := ots_pub.Verify([]byte("example"), ots_sig)
			assert.False(t, result)
		})
	}
}

func TestDoubleSign(t *testing.T) {
	var err error

	id, err := hex.DecodeString("d08fabd4a2091ff0a8cb4ed834e74534")
	assert.NoError(t, err)

	ots_priv, err := ots.NewPrivateKey(common.LMOTS_SHA256_N32_W1, 0, common.ID(id))
	assert.NoError(t, err)

	_, err = ots_priv.Sign([]byte("example"), nil)
	assert.NoError(t, err)
	_, err = ots_priv.Sign([]byte("example2"), nil)
	assert.Error(t, err)
}

func TestOtsPublicKeyFromBytes(t *testing.T) {
	for i := 0; i < 1000; i++ {
		bytes := make([]byte, i)
		_, err := ots.LmsOtsPublicKeyFromBytes(bytes)
		assert.Error(t, err)
	}
}
