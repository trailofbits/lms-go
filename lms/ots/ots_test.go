package ots_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trailofbits/lms-go/lms/common"
	"github.com/trailofbits/lms-go/lms/ots"
)

func testOtsSignVerify(t *testing.T, otstc common.LmsOtsAlgorithmType) {
	var err error

	id, err := hex.DecodeString("d08fabd4a2091ff0a8cb4ed834e74534")
	if err != nil {
		panic(err)
	}

	ots_priv, err := ots.NewPrivateKey(otstc, 0, common.ID(id))
	if err != nil {
		panic(err)
	}

	ots_pub := ots_priv.Public()
	ots_sig, err := ots_priv.Sign([]byte("example"), nil)
	if err != nil {
		panic(err)
	}

	result := ots_pub.Verify([]byte("example"), ots_sig)
	assert.True(t, result)
}

func testOtsSignVerifyFail(t *testing.T, otstc common.LmsOtsAlgorithmType) {
	var err error

	id, err := hex.DecodeString("d08fabd4a2091ff0a8cb4ed834e74534")
	if err != nil {
		panic(err)
	}

	ots_priv, err := ots.NewPrivateKey(otstc, 0, common.ID(id))
	if err != nil {
		panic(err)
	}

	ots_pub := ots_priv.Public()
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
}

func TestOtsSignVerifyW1(t *testing.T) {
	testOtsSignVerify(t, common.LMOTS_SHA256_N32_W1)
}

func TestOtsSignVerifyW2(t *testing.T) {
	testOtsSignVerify(t, common.LMOTS_SHA256_N32_W2)
}

func TestOtsSignVerifyW4(t *testing.T) {
	testOtsSignVerify(t, common.LMOTS_SHA256_N32_W4)
}

func TestOtsSignVerifyW8(t *testing.T) {
	testOtsSignVerify(t, common.LMOTS_SHA256_N32_W8)
}

func TestOtsSignVerifyW1Fail(t *testing.T) {
	testOtsSignVerifyFail(t, common.LMOTS_SHA256_N32_W1)
}

func TestOtsSignVerifyW2Fail(t *testing.T) {
	testOtsSignVerifyFail(t, common.LMOTS_SHA256_N32_W2)
}

func TestOtsSignVerifyW4Fail(t *testing.T) {
	testOtsSignVerifyFail(t, common.LMOTS_SHA256_N32_W4)
}

func TestOtsSignVerifyW8Fail(t *testing.T) {
	testOtsSignVerifyFail(t, common.LMOTS_SHA256_N32_W8)
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
		_, err := ots.LmsOtsPublicKeyFromByes(bytes)
		assert.Error(t, err)
	}
}
