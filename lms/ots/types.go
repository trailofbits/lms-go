package ots

import (
	"github.com/trailofbits/lms-go/lms/common"
)

// A LmsOtsPrivateKey is used to sign exactly one message.
type LmsOtsPrivateKey struct {
	typecode common.LmsOtsAlgorithmType
	q        uint32
	id       common.ID
	x        [][]byte
	valid    bool
}

// A LmsOtsPublicKey is used to verify exactly one message.
type LmsOtsPublicKey struct {
	typecode common.LmsOtsAlgorithmType
	q        uint32
	id       common.ID
	k        []byte
}

// A LmsOtsSignature is a signature of one message.
type LmsOtsSignature struct {
	typecode common.LmsOtsAlgorithmType
	c        []byte
	y        [][]byte
}
