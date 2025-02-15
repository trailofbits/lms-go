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
				t.Fatalf("hex.DecodeString() = %v", err)
			}

			otsPriv, err := ots.NewPrivateKey(common.Uint32ToLmotsType(tc.typecode), 0, common.ID(id))
			if err != nil {
				t.Fatalf("ots.NewPrivateKey() = %v", err)
			}

			otsPub, err := otsPriv.Public()
			if err != nil {
				t.Fatalf("otsPriv.Public() = %v", err)
			}
			otsSig, err := otsPriv.Sign([]byte("example"), nil)
			if err != nil {
				t.Fatalf("otsPriv.Sign() = %v", err)
			}

			t.Run("VerifyOK", func(t *testing.T) {
				result := otsPub.Verify([]byte("example"), otsSig)
				assert.True(t, result)
			})

			t.Run("VerifyBadPubFail", func(t *testing.T) {
				// modify q so that the verification fails
				otsPubBytes := otsPub.ToBytes()
				otsPubBytes[23] ^= 1
				otsPub2, err := ots.LmsOtsPublicKeyFromBytes(otsPubBytes)
				if err != nil {
					t.Fatalf("LmsOtsPublicKeyFromBytes() = %v", err)
				}
				result := otsPub2.Verify([]byte("example"), otsSig)
				assert.False(t, result)
			})

			t.Run("VerifyBadSigFail", func(t *testing.T) {
				// modify sig so that the verification fails
				otsSigBytes, err := otsSig.ToBytes()
				if err != nil {
					t.Fatalf("otsSig.ToBytes() = %v", err)
				}
				otsSigBytes[23] ^= 1
				otsSig2, err := ots.LmsOtsSignatureFromBytes(otsSigBytes)
				if err != nil {
					t.Fatalf("LmsOtsPublicKeyFromBytes() = %v", err)
				}
				result := otsPub.Verify([]byte("example"), otsSig2)
				assert.False(t, result)
			})

			t.Run("VerifyBadMsgFail", func(t *testing.T) {
				// try to verify a different message
				result := otsPub.Verify([]byte("example2"), otsSig)
				assert.False(t, result)
			})
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
