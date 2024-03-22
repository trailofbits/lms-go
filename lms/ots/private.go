// Package ots implements one-time signatures (LM-OTS) for use in LMS
//
// This file implements the private key and signing logic.
package ots

import (
	"github.com/trailofbits/lms-go/lms/common"

	"crypto/rand"
	"encoding/binary"
	"errors"
	"hash"
	"io"
)

func hash_write(h hash.Hash, x []byte) {
	_, err := h.Write(x)
	if err != nil {
		panic("hash.Hash.Write never errors")
	}
}

// NewPrivateKey returns a LmsOtsPrivateKey, seeded by a cryptographically secure
// random number generator.
func NewPrivateKey(tc common.LmsOtsAlgorithmType, q uint32, id common.ID) (LmsOtsPrivateKey, error) {
	// var err error
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

		hash_write(hasher, id[:])
		hash_write(hasher, q_be[:])
		hash_write(hasher, i_be[:])
		hash_write(hasher, []byte{0xff})
		hash_write(hasher, seed)

		x[i] = hasher.Sum(nil)
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

	hash_write(hasher, x.id[:])
	hash_write(hasher, be32[:])
	hash_write(hasher, common.D_PBLC[:])

	for i := uint64(0); i < params.P; i++ {
		tmp = make([]byte, len(x.x[i]))
		copy(tmp, x.x[i])

		for j := uint64(0); j < (uint64(1)<<int(params.W.Window()))-1; j++ {
			inner := params.H.New()

			binary.BigEndian.PutUint32(be32[:], x.q)
			binary.BigEndian.PutUint16(be16[:], uint16(i))

			hash_write(inner, x.id[:])
			hash_write(inner, be32[:])
			hash_write(inner, be16[:])
			hash_write(inner, []byte{byte(j)})
			hash_write(inner, tmp)

			tmp = inner.Sum(nil)
		}

		hash_write(hasher, tmp)
	}

	return LmsOtsPublicKey{
		typecode: x.typecode,
		q:        x.q,
		id:       x.id,
		k:        hasher.Sum(nil),
	}, nil
}

// Sign calculates the LM-OTS signature of a chosen message.
// The rng argument is optional. If nil is provided, crypto/rand.Reader will be used.
func (x *LmsOtsPrivateKey) Sign(msg []byte, rng io.Reader) (LmsOtsSignature, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if !x.valid {
		return LmsOtsSignature{}, errors.New("invalid private key")
	}

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

	hash_write(hasher, x.id[:])
	hash_write(hasher, be32[:])
	hash_write(hasher, common.D_MESG[:])
	hash_write(hasher, c)
	hash_write(hasher, msg)

	q := hasher.Sum(nil)
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

			hash_write(inner, x.id[:])
			hash_write(inner, be32[:])
			hash_write(inner, be16[:])
			hash_write(inner, []byte{byte(j)})
			hash_write(inner, y[i])

			y[i] = inner.Sum(nil)
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
