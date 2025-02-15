// Package ots implements one-time signatures (LM-OTS) for use in LMS
//
// This file implements the private key and signing logic.
package ots

import (
	"github.com/trailofbits/lms-go/lms/common"

	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

// NewPrivateKey returns a LmsOtsPrivateKey, seeded by a cryptographically secure
// random number generator.
func NewPrivateKey(tc common.LmsOtsAlgorithmType, q uint32, id common.ID) (LmsOtsPrivateKey, error) {
	params, err := tc.Params()
	if err != nil {
		return LmsOtsPrivateKey{}, err
	}

	seed := make([]byte, params.N)
	_, err = rand.Read(seed)
	if err != nil {
		return LmsOtsPrivateKey{}, err
	}

	return NewPrivateKeyFromSeed(tc, q, id, seed)
}

// NewPrivateKeyFromSeed returns a new LmsOtsPrivateKey, using the algorithm from
// Appendix A of <https://datatracker.ietf.org/doc/html/rfc8554#appendix-A>
func NewPrivateKeyFromSeed(tc common.LmsOtsAlgorithmType, q uint32, id common.ID, seed []byte) (LmsOtsPrivateKey, error) {
	params, err := tc.Params()
	if err != nil {
		return LmsOtsPrivateKey{}, err
	}
	x := make([][]byte, params.P)

	for i := uint64(0); i < params.P; i++ {
		var q_be [4]byte
		var i_be [2]byte
		hasher := params.H.New()

		binary.BigEndian.PutUint32(q_be[:], q)
		binary.BigEndian.PutUint16(i_be[:], uint16(i))

		common.HashWrite(hasher, id[:])
		common.HashWrite(hasher, q_be[:])
		common.HashWrite(hasher, i_be[:])
		common.HashWrite(hasher, []byte{0xff})
		common.HashWrite(hasher, seed)

		x[i] = common.HashSum(hasher, params.N)
	}

	return LmsOtsPrivateKey{
		typecode: tc,
		q:        q,
		id:       id,
		x:        x,
		valid:    true,
	}, nil
}

// Public returns an LmsOtsPublicKey that validates signatures for this private key.
func (x *LmsOtsPrivateKey) Public() (LmsOtsPublicKey, error) {
	var be16 [2]byte
	var be32 [4]byte
	var tmp []byte
	params, err := x.typecode.Params()
	if err != nil {
		return LmsOtsPublicKey{}, err
	}
	hasher := params.H.New()
	binary.BigEndian.PutUint32(be32[:], x.q)

	common.HashWrite(hasher, x.id[:])
	common.HashWrite(hasher, be32[:])
	common.HashWrite(hasher, common.D_PBLC[:])

	for i := uint64(0); i < params.P; i++ {
		tmp = make([]byte, len(x.x[i]))
		copy(tmp, x.x[i])

		for j := uint64(0); j < (uint64(1)<<int(params.W.Window()))-1; j++ {
			inner := params.H.New()

			binary.BigEndian.PutUint32(be32[:], x.q)
			binary.BigEndian.PutUint16(be16[:], uint16(i))

			common.HashWrite(inner, x.id[:])
			common.HashWrite(inner, be32[:])
			common.HashWrite(inner, be16[:])
			common.HashWrite(inner, []byte{byte(j)})
			common.HashWrite(inner, tmp)

			tmp = common.HashSum(inner, params.N)
		}

		common.HashWrite(hasher, tmp)
	}

	return LmsOtsPublicKey{
		typecode: x.typecode,
		q:        x.q,
		id:       x.id,
		k:        common.HashSum(hasher, params.N),
	}, nil
}

// Sign calculates the LM-OTS signature of a chosen message.
// The rng argument is optional. If nil is provided, crypto/rand.Reader will be used.
func (x *LmsOtsPrivateKey) Sign(msg []byte, rng io.Reader) (LmsOtsSignature, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if !x.valid {
		return LmsOtsSignature{}, errors.New("Sign(): invalid private key")
	}

	var err error
	var be16 [2]byte
	var be32 [4]byte
	params, err := x.typecode.Params()
	if err != nil {
		return LmsOtsSignature{}, err
	}
	hasher := params.H.New()
	c := make([]byte, params.N)

	_, err = rng.Read(c)
	if err != nil {
		return LmsOtsSignature{}, err
	}

	binary.BigEndian.PutUint32(be32[:], x.q)

	common.HashWrite(hasher, x.id[:])
	common.HashWrite(hasher, be32[:])
	common.HashWrite(hasher, common.D_MESG[:])
	common.HashWrite(hasher, c)
	common.HashWrite(hasher, msg)

	q := common.HashSum(hasher, params.N)
	expanded, err := common.Expand(q, x.typecode)
	if err != nil {
		return LmsOtsSignature{}, err
	}

	y := make([][]byte, params.P)

	for i := uint64(0); i < params.P; i++ {
		a := uint64(expanded[i])
		y[i] = make([]byte, len(x.x[i]))
		copy(y[i], x.x[i])

		for j := uint64(0); j < a; j++ {
			inner := params.H.New()

			binary.BigEndian.PutUint32(be32[:], x.q)
			binary.BigEndian.PutUint16(be16[:], uint16(i))

			common.HashWrite(inner, x.id[:])
			common.HashWrite(inner, be32[:])
			common.HashWrite(inner, be16[:])
			common.HashWrite(inner, []byte{byte(j)})
			common.HashWrite(inner, y[i])

			y[i] = common.HashSum(inner, params.N)
		}

		// y[i] is now the correct value
	}

	// mark private key as invalid
	x.x = nil
	x.valid = false

	return LmsOtsSignature{
		typecode: x.typecode,
		c:        c,
		y:        y,
	}, nil
}
