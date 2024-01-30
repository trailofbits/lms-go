// Package ots implements one-time signatures (LM-OTS) for use in LMS
//
// This file implements the signature (including serialization).
package ots

import (
	"encoding/binary"
	"errors"

	"github.com/trailofbits/lms/lms/common"
)

// LmsOtsSignatureFromBytes returns an LmsOtsSignature represented by b.
func LmsOtsSignatureFromBytes(b []byte) (LmsOtsSignature, error) {
	if len(b) < 4 {
		return LmsOtsSignature{}, errors.New("No typecode")
	}

	// Typecode is the first 4 bytes
	typecode := common.Uint32ToLmsType(binary.BigEndian.Uint32(b[0:4]))
	// Panic if not a valid LM-OTS algorithm:
	params := typecode.Params()

	// check the length of the signature
	if uint64(len(b)) < params.SIG_LEN {
		return LmsOtsSignature{}, errors.New("LMOTS signature too short")
	} else if uint64(len(b)) > params.SIG_LEN {
		return LmsOtsSignature{}, errors.New("LMOTS signature too long")
	} else {
		// parse the signature
		c := b[4 : 4+int(params.N)]
		cur := uint64(4 + params.N)

		y := make([][]byte, params.P)
		for i := uint64(0); i < params.P; i++ {
			y[i] = b[cur : cur+params.N]
			cur += params.N
		}

		return LmsOtsSignature{
			typecode: typecode,
			c:        c,
			y:        y,
		}, nil
	}
}

// ToBytes() serializes the LM-OTS signature into a byte string for transmission or storage.
func (sig *LmsOtsSignature) ToBytes() ([]byte, error) {
	var serialized []byte
	var u32_be [4]byte
	params := sig.typecode.Params()

	// First 4 bytes: LMOTS typecode
	typecode, err := sig.typecode.LmsOtsType()
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(u32_be[:], typecode.ToUint32())
	serialized = append(serialized, u32_be[:]...)

	// Next H bytes: nonce C
	serialized = append(serialized, sig.c...)

	// Next P * H bytes: y[0] ... y[p-1]
	for i := uint64(0); i < params.P; i++ {
		serialized = append(serialized, sig.y[i]...)
	}

	return serialized, nil
}
