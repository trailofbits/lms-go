// Package ots implements one-time signatures (LM-OTS) for use in LMS
//
// This file implements the public key and verification logic.
package ots

import (
	"github.com/trailofbits/lms-go/lms/common"

	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// Verify returns true if sig is valid for msg and this public key.
// It returns false otherwise.
func (pub *LmsOtsPublicKey) Verify(msg []byte, sig LmsOtsSignature) bool {
	// try to recover the public key
	kc, valid := sig.RecoverPublicKey(msg, pub.typecode, pub.id, pub.q)

	// this short circuits if valid == false and does the key comparison otherwise
	return valid && subtle.ConstantTimeCompare(pub.k, kc.k) == 1
}

// RecoverPublicKey calculates the public key for a given message.
// This is used in signature verification.
func (sig *LmsOtsSignature) RecoverPublicKey(msg []byte, pubtype common.LmsOtsAlgorithmType, id common.ID, q uint32) (LmsOtsPublicKey, bool) {
	var be16 [2]byte
	var be32 [4]byte
	var tmp []byte

	// algorithm 4b step 2.b
	if pubtype != sig.typecode {
		return LmsOtsPublicKey{}, false
	}

	params, err := sig.typecode.Params()
	if err != nil {
		return LmsOtsPublicKey{}, false
	}
	hasher := params.H.New()
	hash_len := int(params.N)

	// verify length of nonce
	if len(sig.c) != hash_len {
		return LmsOtsPublicKey{}, false
	}

	// verify length of y and y[i]
	if uint64(len(sig.y)) != params.P {
		return LmsOtsPublicKey{}, false
	}
	for i := uint64(0); i < params.P; i++ {
		if len(sig.y[i]) != hash_len {
			return LmsOtsPublicKey{}, false
		}
	}

	binary.BigEndian.PutUint32(be32[:], q)

	common.HashWrite(hasher, id[:])
	common.HashWrite(hasher, be32[:])
	common.HashWrite(hasher, common.D_MESG[:])
	common.HashWrite(hasher, sig.c)
	common.HashWrite(hasher, msg)

	Q := common.HashSum(hasher, params.N)
	expanded, err := common.Expand(Q, sig.typecode)
	if err != nil {
		return LmsOtsPublicKey{}, false
	}

	hasher.Reset()
	common.HashWrite(hasher, id[:])
	common.HashWrite(hasher, be32[:])
	common.HashWrite(hasher, common.D_PBLC[:])

	for i := uint64(0); i < params.P; i++ {
		a := uint64(expanded[i])
		tmp = make([]byte, len(sig.y[i]))
		copy(tmp, sig.y[i])

		for j := uint64(a); j < (uint64(1)<<int(params.W.Window()))-1; j++ {
			inner := params.H.New()

			binary.BigEndian.PutUint32(be32[:], q)
			binary.BigEndian.PutUint16(be16[:], uint16(i))

			common.HashWrite(inner, id[:])
			common.HashWrite(inner, be32[:])
			common.HashWrite(inner, be16[:])
			common.HashWrite(inner, []byte{byte(j)})
			common.HashWrite(inner, tmp)

			tmp = common.HashSum(inner, params.N)
		}

		common.HashWrite(hasher, tmp)
	}

	return LmsOtsPublicKey{
		typecode: sig.typecode,
		q:        q,
		id:       id,
		k:        common.HashSum(hasher, params.N),
	}, true
}

// Key returns a copy of the public key's k parameter.
// We need this to get the public key as bytes in order to hash
func (pub *LmsOtsPublicKey) Key() []byte {
	return pub.k[:]
}

// LmsOtsPublicKeyFromBytes returns an LmsOtsPublicKey that represents b.
// This is the inverse of the ToBytes() method on the LmsOtsPublicKey object.
func LmsOtsPublicKeyFromBytes(b []byte) (LmsOtsPublicKey, error) {
	if len(b) < 4 {
		return LmsOtsPublicKey{}, errors.New("LmsOtsPublicKeyFromBytes(): OTS public key too short")
	}
	// The typecode is bytes 0-3 (4 bytes)
	typecode, err := common.Uint32ToLmotsType(binary.BigEndian.Uint32(b[0:4])).LmsOtsType()
	if err != nil {
		return LmsOtsPublicKey{}, err
	}
	// ensure that it is valid
	params, err := typecode.Params()
	if err != nil {
		return LmsOtsPublicKey{}, err
	}

	// ensure that the length of the slice is correct
	if uint64(len(b)) < 4+common.ID_LEN+4+params.N {
		return LmsOtsPublicKey{}, errors.New("LmsOtsPublicKeyFromBytes(): OTS public key too short")
	} else if uint64(len(b)) > 4+common.ID_LEN+4+params.N {
		return LmsOtsPublicKey{}, errors.New("LmsOtsPublicKeyFromBytes(): OTS public key too long")
	} else {
		// The next ID_LEN bytes are the id
		id := common.ID(b[4 : 4+common.ID_LEN])

		// the next 4 bytes is the internal counter q
		q := binary.BigEndian.Uint32(b[4+common.ID_LEN : 8+common.ID_LEN])

		// The public key, k, is the remaining bytes
		k := b[8+common.ID_LEN:]

		return LmsOtsPublicKey{
			typecode: typecode,
			id:       id,
			q:        q,
			k:        k,
		}, nil
	}
}

// ToBytes() serializes the public key into a byte string for transmission or storage.
func (pub *LmsOtsPublicKey) ToBytes() []byte {
	var serialized []byte
	var u32_be [4]byte

	// First 4 bytes: typecode
	typecode, _ := pub.typecode.LmsOtsType()
	// This will never error if we have a valid LmsOtsPublicKey
	binary.BigEndian.PutUint32(u32_be[:], typecode.ToUint32())
	serialized = append(serialized, u32_be[:]...)

	// Next 16 bytes: id
	serialized = append(serialized, pub.id[:]...)

	// Next 4 bytes: q
	binary.BigEndian.PutUint32(u32_be[:], pub.q)
	serialized = append(serialized, u32_be[:]...)

	// Followed by the public key, k
	serialized = append(serialized, pub.k[:]...)

	return serialized
}
