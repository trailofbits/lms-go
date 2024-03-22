// Package lms implements Leighton-Micali Hash-Based Signatures (RFC 8554)
//
// This file implements the private key and signing logic.
package lms

import (
	"encoding/binary"
	"errors"

	"github.com/trailofbits/lms-go/lms/common"
	"github.com/trailofbits/lms-go/lms/ots"

	"crypto/rand"
	"hash"
	"io"
)

func hash_write(h hash.Hash, x []byte) {
	_, err := h.Write(x)
	if err != nil {
		panic("hash.Hash.Write never errors")
	}
}

// NewPrivateKey returns a LmsPrivateKey, seeded by a cryptographically secure
// random number generator.
func NewPrivateKey(tc common.LmsAlgorithmType, otstc common.LmsOtsAlgorithmType) (LmsPrivateKey, error) {
	var err error
	tc, err = tc.LmsType()
	if err != nil {
		return LmsPrivateKey{}, err
	}
	params, err := tc.LmsParams()
	if err != nil {
		return LmsPrivateKey{}, err
	}

	seed := make([]byte, params.M)
	_, err = rand.Read(seed)
	if err != nil {
		return LmsPrivateKey{}, err
	}
	idbytes := make([]byte, common.ID_LEN)
	_, err = rand.Read(idbytes)
	if err != nil {
		return LmsPrivateKey{}, err
	}
	id := common.ID(idbytes)

	return NewPrivateKeyFromSeed(tc, otstc, id, seed)
}

// NewPrivateKeyFromSeed returns a new LmsPrivateKey, using the algorithm from
// Appendix A of <https://datatracker.ietf.org/doc/html/rfc8554#appendix-A>
func NewPrivateKeyFromSeed(tc common.LmsAlgorithmType, otstc common.LmsOtsAlgorithmType, id common.ID, seed []byte) (LmsPrivateKey, error) {
	tc, err := tc.LmsType()
	if err != nil {
		return LmsPrivateKey{}, err
	}
	otstc, err = otstc.LmsOtsType()
	if err != nil {
		return LmsPrivateKey{}, err
	}
	tree, err := GeneratePKTree(tc, otstc, id, seed)
	if err != nil {
		return LmsPrivateKey{}, err
	}
	return LmsPrivateKey{
		typecode: tc,
		otstype:  otstc,
		q:        0,
		id:       id,
		seed:     seed,
		authtree: tree,
	}, nil
}

// Public returns an LmsPublicKey that validates signatures for this private key
func (priv *LmsPrivateKey) Public() LmsPublicKey {
	return LmsPublicKey{
		typecode: priv.typecode,
		otstype:  priv.otstype,
		id:       priv.id,
		k:        priv.authtree[0],
	}
}

// Sign calculates the LMS signature of a chosen message.
// The rng argument is optional. If nil is provided, crypto/rand.Reader will be used.
func (priv *LmsPrivateKey) Sign(msg []byte, rng io.Reader) (LmsSignature, error) {
	if rng == nil {
		rng = rand.Reader
	}
	params, err := priv.typecode.LmsParams()
	if err != nil {
		return LmsSignature{}, err
	}
	height := int(params.H)
	var leaves uint32 = 1 << height
	if priv.q >= leaves {
		return LmsSignature{}, errors.New("Sign(): invalid private key")
	}
	// ots_params := ots_tc.Params()
	ots_priv, err := ots.NewPrivateKeyFromSeed(priv.otstype, priv.q, priv.id, priv.seed)
	if err != nil {
		return LmsSignature{}, err
	}
	ots_sig, err := ots_priv.Sign(msg, rng)
	if err != nil {
		return LmsSignature{}, err
	}
	authpath := make([][]byte, params.H)

	var r uint32 = leaves + priv.q
	var temp uint32
	for i := 0; i < height; i++ {
		temp = (r >> i) ^ 1
		// We use x-1 because T[x] is indexed from 1, not 0, in the spec
		authpath[i] = priv.authtree[temp-1][:]
	}

	// We incremenet q to signal the this keys should not be reused
	priv.incrementQ()

	return LmsSignature{
		priv.typecode,
		priv.q - 1,
		ots_sig,
		authpath,
	}, nil
}

// Private
func (priv *LmsPrivateKey) incrementQ() {
	priv.q++
}

// ToBytes() serialized the private key into a byte string for storage.
// The current value of the internal counter, q, is included.
func (priv *LmsPrivateKey) ToBytes() []byte {
	var serialized []byte
	var u32_be [4]byte

	// First 4 bytes: typecode
	typecode, _ := priv.typecode.LmsType()
	// ToBytes() is only ever called on a valid object, so this will never return an error
	binary.BigEndian.PutUint32(u32_be[:], typecode.ToUint32())
	serialized = append(serialized, u32_be[:]...)

	// Next 4 bytes: OTS typecode
	otstype, _ := priv.otstype.LmsOtsType()
	// ToBytes() is only ever called on a valid object, so this will never return an error
	binary.BigEndian.PutUint32(u32_be[:], otstype.ToUint32())
	serialized = append(serialized, u32_be[:]...)

	// Next 4 bytes: q
	binary.BigEndian.PutUint32(u32_be[:], priv.q)
	serialized = append(serialized, u32_be[:]...)

	// Next 16 bytes: id
	serialized = append(serialized, priv.id[:]...)

	// Next 32 bytes: seed
	serialized = append(serialized, priv.seed[:]...)

	// We don't need to serialize the authtree
	return serialized
}

// Retrieve the current value of the internal counter, q.
// Used for unit tests
func (priv *LmsPrivateKey) Q() uint32 {
	return priv.q
}

// LmsPrivateKeyFromBytes returns an LmsPrivateKey that represents b.
// This is the inverse of the ToBytes() method on the LmsPrivateKey object.
func LmsPrivateKeyFromBytes(b []byte) (LmsPrivateKey, error) {
	if len(b) < 8 {
		return LmsPrivateKey{}, errors.New("LmsPrivateKeyFromBytes(): Input is too short")
	}

	// The typecode is bytes 0-3 (4 bytes)
	typecode, err := common.Uint32ToLmsType(binary.BigEndian.Uint32(b[0:4])).LmsType()
	if err != nil {
		return LmsPrivateKey{}, err
	}
	// The OTS typecode is bytes 4-7 (4 bytes)
	otstype, err := common.Uint32ToLmsType(binary.BigEndian.Uint32(b[4:8])).LmsOtsType()
	if err != nil {
		return LmsPrivateKey{}, err
	}
	lmsparams, err := typecode.LmsParams()
	if err != nil {
		return LmsPrivateKey{}, err
	}
	if len(b) < int(lmsparams.M+28) {
		return LmsPrivateKey{}, errors.New("LmsPrivateKeyFromBytes(): Input is too short")
	}

	// Internal counter is bytes 8-11 (4 bytes)
	q := binary.BigEndian.Uint32(b[8:12])
	// ID is bytes 12-27 (16 bytes)
	id := common.ID(b[12:28])
	// Seed is bytes 28+ (32 bytes for SHA-256)
	seed_end := lmsparams.M + 28
	seed := b[28:seed_end]

	// Load private key, then set q to what was persisted
	privateKey, err := NewPrivateKeyFromSeed(typecode, otstype, id, seed)
	if err != nil {
		return LmsPrivateKey{}, err
	}
	privateKey.q = q
	return privateKey, nil
}

// GeneratePKTree generates the Merkle Tree needed to derive the public key and
// authentication path for any message.
func GeneratePKTree(tc common.LmsAlgorithmType, otstc common.LmsOtsAlgorithmType, id common.ID, seed []byte) ([][]byte, error) {
	params, err := tc.LmsParams()
	if err != nil {
		return nil, err
	}
	ots_params, err := otstc.Params()
	if err != nil {
		return nil, err
	}

	var tree_nodes uint32 = (1 << (params.H + 1)) - 1
	var leaves uint32 = 1 << params.H
	var authtree = make([][]byte, tree_nodes)
	var i uint32
	var j uint32

	var r uint32
	var r_be [4]byte
	for i = 0; i < leaves; i++ {
		r = i + leaves
		ots_priv, err := ots.NewPrivateKeyFromSeed(otstc, i, id, seed)
		if err != nil {
			return nil, err
		}
		ots_pub, err := ots_priv.Public()
		if err != nil {
			return nil, err
		}

		binary.BigEndian.PutUint32(r_be[:], r)

		hasher := ots_params.H.New()
		hash_write(hasher, id[:])
		hash_write(hasher, r_be[:])
		hash_write(hasher, common.D_LEAF[:])
		hash_write(hasher, ots_pub.Key())
		authtree[r-1] = hasher.Sum(nil)

		j = i
		for j%2 == 1 {
			r = (r - 1) >> 1
			j = (j - 1) >> 1
			hasher := ots_params.H.New()

			binary.BigEndian.PutUint32(r_be[:], r)

			hash_write(hasher, id[:])
			hash_write(hasher, r_be[:])
			hash_write(hasher, common.D_INTR[:])
			hash_write(hasher, authtree[2*r-1])
			hash_write(hasher, authtree[2*r])
			authtree[r-1] = hasher.Sum(nil)
		}
	}
	return authtree, nil
}
