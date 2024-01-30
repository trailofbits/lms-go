package lms

import (
	"github.com/trailofbits/lms-go/lms/common"
	"github.com/trailofbits/lms-go/lms/ots"
)

// A LmsPrivateKey is used to sign a finite number of messages
type LmsPrivateKey struct {
	typecode common.LmsAlgorithmType
	otstype  common.LmsOtsAlgorithmType
	q        uint32
	id       common.ID
	seed     []byte
	authtree [][]byte
}

// A LmsPublicKey is used to verify messages signed by a LmsPrivateKey
type LmsPublicKey struct {
	typecode common.LmsAlgorithmType
	otstype  common.LmsOtsAlgorithmType
	id       common.ID
	k        []byte
}

// A LmsSignature represents a signature produced by an LmsPrivateKey
// which an LmsPublicKey can validate for a given message
type LmsSignature struct {
	typecode common.LmsAlgorithmType
	q        uint32
	ots      ots.LmsOtsSignature
	path     [][]byte
}
