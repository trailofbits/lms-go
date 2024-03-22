package lms_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trailofbits/lms-go/lms/common"
	"github.com/trailofbits/lms-go/lms/lms"
)

func TestPKTreeKAT1(t *testing.T) {
	seed, err := hex.DecodeString("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439")
	if err != nil {
		panic(err)
	}

	id, err := hex.DecodeString("d08fabd4a2091ff0a8cb4ed834e74534")
	if err != nil {
		panic(err)
	}

	expected_k, err := hex.DecodeString("32a58885cd9ba0431235466bff9651c6c92124404d45fa53cf161c28f1ad5a8e")
	if err != nil {
		panic(err)
	}
	tc := common.LMS_SHA256_M32_H10
	otstc := common.LMOTS_SHA256_N32_W4

	lms_priv, err := lms.NewPrivateKeyFromSeed(tc, otstc, common.ID(id), seed)
	assert.NoError(t, err)
	lms_pub := lms_priv.Public()

	assert.Equal(t, lms_pub.ID(), common.ID(id))
	assert.Equal(t, lms_pub.Key(), expected_k)

}

func TestBadPrivateKeyPanics(t *testing.T) {
	priv_bytes, err := hex.DecodeString(
		"000000060000000300000005" +
			"d08fabd4a2091ff0a8cb4ed834e74534" +
			"558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439",
	)
	if err != nil {
		panic(err)
	}

	// This should panic
	priv_bytes[6] = 0xff
	_, err = lms.LmsPrivateKeyFromBytes(priv_bytes)
	assert.NotNil(t, err)
}

func TestShortPrivateKeyReturnsError(t *testing.T) {
	priv_bytes, err := hex.DecodeString("000000060000000300000005d08fabd4a2091ff0a8cb4ed834e74534")
	if err != nil {
		panic(err)
	}
	_, err = lms.LmsPrivateKeyFromBytes(priv_bytes)
	assert.NotNil(t, err)
}

func TestSignKAT1(t *testing.T) {
	lms_priv_bytes, err := hex.DecodeString(
		"000000060000000300000005" +
			"d08fabd4a2091ff0a8cb4ed834e74534" +
			"558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439",
	)
	if err != nil {
		panic(err)
	}
	lms_priv, err := lms.LmsPrivateKeyFromBytes(lms_priv_bytes)
	if err != nil {
		panic(err)
	}
	assert.Equal(t, lms_priv.Q(), uint32(5))
	reserialized := lms_priv.ToBytes()
	assert.Equal(t, reserialized, lms_priv_bytes)

	// Test an actual signed message
	msg, err := hex.DecodeString(
		"54686520706f77657273206e6f742064" +
			"656c65676174656420746f2074686520" +
			"556e6974656420537461746573206279" +
			"2074686520436f6e737469747574696f" +
			"6e2c206e6f722070726f686962697465" +
			"6420627920697420746f207468652053" +
			"74617465732c20617265207265736572" +
			"76656420746f20746865205374617465" +
			"7320726573706563746976656c792c20" +
			"6f7220746f207468652070656f706c65" +
			"2e0a")
	if err != nil {
		panic(err)
	}

	// Generate a signature
	sig, err := lms_priv.Sign(msg, nil)
	assert.NoError(t, err)

	// Assert incremented
	assert.Equal(t, lms_priv.Q(), uint32(6))

	// Get the public key
	lms_public := lms_priv.Public()
	expected_public_key, err := hex.DecodeString(
		"0000000600000003" +
			"d08fabd4a2091ff0a8cb4ed834e74534" +
			"32a58885cd9ba0431235466bff9651c6" +
			"c92124404d45fa53cf161c28f1ad5a8e",
	)
	if err != nil {
		panic(err)
	}
	assert.Equal(t, expected_public_key, lms_public.ToBytes())

	// Verify the signature is true
	result := lms_public.Verify(msg, sig)
	assert.True(t, result)

	// Is the signature as long as we expect?
	sigbytes, err := sig.ToBytes()
	if err != nil {
		panic(err)
	}
	siglen := len(sigbytes)
	assert.Equal(t, 2508, siglen)

	// Let's change the signature, then ensure it returns false
	// We use XOR to flip the last bit
	sigbytes[siglen-1] ^= 1
	sig2, err := lms.LmsSignatureFromBytes(sigbytes)
	if err != nil {
		panic(err)
	}
	// Flipping a bit in the signature should yield a false
	result = lms_public.Verify(msg, sig2)
	assert.False(t, result)
}

func TestShortSignatureFromBytes(t *testing.T) {
	for i := 0; i < 1000; i++ {
		data := make([]byte, i)
		_, err := lms.LmsSignatureFromBytes(data)
		assert.Error(t, err)
	}
}
