// Package lms implements Leighton-Micali Hash-Based Signatures (RFC 8554)
//
// This file implements the public key and signature verification logic.
package lms

import (
	"github.com/trailofbits/lms-go/lms/common"

	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// NewPublicKey return a new LmsPublicKey, given the LMS typecode, LM-OTS typecode, ID, and
// root of the authentication tree (called k).
func NewPublicKey(tc common.LmsAlgorithmType, otstc common.LmsOtsAlgorithmType, id common.ID, k []byte) (LmsPublicKey, error) {
	// Explicit check from Algorithm 6, Step 1 of RFC 8554
	if len(k) < 8 {
		return LmsPublicKey{}, errors.New("invalid public key")
	}

	var err error
	tc, err = tc.LmsType()
	if err != nil {
		return LmsPublicKey{}, err
	}
	otstc, err = otstc.LmsOtsType()
	if err != nil {
		return LmsPublicKey{}, err
	}

	return LmsPublicKey{
		typecode: tc,
		otstype:  otstc,
		id:       id,
		k:        k[:],
	}, nil
}

// Verify returns true if sig is valid for msg and this public key.
// It returns false otherwise.
func (pub *LmsPublicKey) Verify(msg []byte, sig LmsSignature) bool {
	params, err := pub.typecode.LmsParams()
	if err != nil {
		return false
	}
	ots_params, err := pub.otstype.Params()
	if err != nil {
		return false
	}
	height := int(params.H)
	leaves := uint32(1 << height)

	key_candidate, valid := sig.ots.RecoverPublicKey(msg, pub.id, sig.q)
	if !valid {
		return false
	}
	node_num := sig.q + leaves
	var node_num_bytes [4]byte
	var tmp_be [4]byte
	binary.BigEndian.PutUint32(node_num_bytes[:], node_num)

	hasher := ots_params.H.New()
	hash_write(hasher, pub.id[:])
	hash_write(hasher, node_num_bytes[:])
	hash_write(hasher, common.D_LEAF[:])
	hash_write(hasher, key_candidate.Key())
	tmp := hasher.Sum(nil)

	for i := 0; i < height; i++ {
		binary.BigEndian.PutUint32(tmp_be[:], node_num>>1)

		hasher := ots_params.H.New()
		hash_write(hasher, pub.id[:])
		hash_write(hasher, tmp_be[:])
		hash_write(hasher, common.D_INTR[:])
		if node_num%2 == 1 {
			hash_write(hasher, sig.path[i])
			hash_write(hasher, tmp)
		} else {
			hash_write(hasher, tmp)
			hash_write(hasher, sig.path[i])
		}
		tmp = hasher.Sum(nil)
		node_num >>= 1
	}
	return subtle.ConstantTimeCompare(tmp, pub.k) == 1
}

// ToBytes() serializes the public key into a byte string for transmission or storage.
func (pub *LmsPublicKey) ToBytes() []byte {
	var serialized []byte
	var u32_be [4]byte

	// First 4 bytes: typecode
	typecode, _ := pub.typecode.LmsType()
	// ToBytes() is only ever called on a valid object, so this will never return an error
	binary.BigEndian.PutUint32(u32_be[:], typecode.ToUint32())
	serialized = append(serialized, u32_be[:]...)

	// Next 4 bytes: OTS typecode
	otstype, _ := pub.otstype.LmsOtsType()
	// ToBytes() is only ever called on a valid object, so this will never return an error
	binary.BigEndian.PutUint32(u32_be[:], otstype.ToUint32())
	serialized = append(serialized, u32_be[:]...)

	// Next 16 bytes: id
	serialized = append(serialized, pub.id[:]...)

	// Followed by the public key, k
	serialized = append(serialized, pub.k[:]...)

	return serialized
}

// Return a []byte representing the actual public key, k, which is the root of the
// authentication path in the corresponding private key.
// We need this to get the public key as bytes in order to test
func (pub *LmsPublicKey) Key() []byte {
	return pub.k[:]
}

// Return the ID for this public key
func (pub *LmsPublicKey) ID() common.ID {
	return pub.id
}

// LmsPublicKeyFromBytes returns an LmsPublicKey that represents b.
// This is the inverse of the ToBytes() method on the LmsPublicKey object.
func LmsPublicKeyFromByes(b []byte) (LmsPublicKey, error) {
	if len(b) < 8 {
		return LmsPublicKey{}, errors.New("key must be more than 8 bytes long")
	}
	// The typecode is bytes 0-3 (4 bytes)
	typecode, err := common.Uint32ToLmsType(binary.BigEndian.Uint32(b[0:4])).LmsType()
	if err != nil {
		return LmsPublicKey{}, err
	}
	// The OTS typecode is bytes 4-7 (4 bytes)
	otstype, err := common.Uint32ToLmsType(binary.BigEndian.Uint32(b[4:8])).LmsOtsType()
	if err != nil {
		return LmsPublicKey{}, err
	}
	if len(b) < 24 {
		return LmsPublicKey{}, errors.New("input is too short")
	}
	// The ID is bytes 8-23 (16 bytes)
	id := common.ID(b[8:24])
	// The public key, k, is the remaining bytes
	k := b[24:]

	// Ensure k is the correct length
	lmsparams, err := typecode.LmsParams()
	if err != nil {
		return LmsPublicKey{}, err
	}
	if uint64(len(k)) != lmsparams.M {
		return LmsPublicKey{}, errors.New("invalid key length")
	}

	return LmsPublicKey{
		typecode: typecode,
		otstype:  otstype,
		id:       id,
		k:        k,
	}, nil
}
