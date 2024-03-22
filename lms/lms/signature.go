// Package lms implements Leighton-Micali Hash-Based Signatures (RFC 8554)
//
// This file implements the LmsSignature type, including serialization.
package lms

import (
	"github.com/trailofbits/lms-go/lms/common"
	"github.com/trailofbits/lms-go/lms/ots"

	"encoding/binary"
	"errors"
)

// NewLmsSignature returns a LmsSignature, given an LMS algorithm type, internal counter,
// LM-OTS signature, and authentication path.
func NewLmsSignature(tc common.LmsAlgorithmType, q uint32, otsig ots.LmsOtsSignature, path [][]byte) (LmsSignature, error) {
	tc, err := tc.LmsType()
	if err != nil {
		return LmsSignature{}, err
	}
	params, err := tc.LmsParams()
	if err != nil {
		return LmsSignature{}, err
	}
	var tmp uint32 = 1 << params.H

	// From step 2i of Algorithm 6a in RFC 8554
	if q >= tmp {
		return LmsSignature{}, errors.New("NewLmsSignature(): Invalid signature")
	}

	// There should be H elements in the authpath
	if uint64(len(path)) != params.H {
		return LmsSignature{}, errors.New("NewLmsSignature(): Invalid signature authentication path")
	}

	return LmsSignature{
		typecode: tc,
		q:        q,
		ots:      otsig,
		path:     path,
	}, nil
}

// LmsSignatureFromBytes returns an LmsSignature represented by b.
// This is the inverse of the ToBytes() on LmsSignature.
func LmsSignatureFromBytes(b []byte) (LmsSignature, error) {
	if len(b) < 8 {
		return LmsSignature{}, errors.New("LmsSignatureFromBytes(): Signature is too short")
	}

	var err error

	// The internal counter is bytes 0-3
	q := binary.BigEndian.Uint32(b[0:4])

	// The OTS signature starts at byte 4, with the typecode first
	otstc := common.Uint32ToLmsType(binary.BigEndian.Uint32(b[4:8]))
	// Return error if not a valid LM-OTS algorithm:
	_, err = otstc.LmsOtsType()
	if err != nil {
		return LmsSignature{}, err
	}

	// 4 + LM-OTS signature length is the first byte after the LM-OTS sig
	otssiglen, err := otstc.LmsOtsSigLength()
	if err != nil {
		return LmsSignature{}, err
	}
	otsigmax := 4 + otssiglen
	if uint64(4+len(b)) <= otsigmax {
		// We are only ensuring that we can read the LMS typecode
		return LmsSignature{}, errors.New("LmsSignatureFromBytes(): Signature is too short for LM-OTS typecode")
	}
	// Now that we know we have enough bytes for LMS, look at the typecode
	typecode := common.Uint32ToLmsType(binary.BigEndian.Uint32(b[otsigmax : otsigmax+4]))
	// Return error if not a valid LMS algorithm
	_, err = typecode.LmsType()
	if err != nil {
		return LmsSignature{}, err
	}

	// With both typecodes, we can calculate the total signature length
	siglen, err := typecode.LmsSigLength(otstc)
	if err != nil {
		return LmsSignature{}, err
	}
	if siglen != uint64(len(b)) {
		return LmsSignature{}, errors.New("LmsSignatureFromBytes(): Invalid LMS signature length")
	}

	// currenly undefined func
	otsig, err := ots.LmsOtsSignatureFromBytes(b[4:otsigmax])
	if err != nil {
		return LmsSignature{}, err
	}

	// With the lengths and OTS sig in hand, we can now parse the LMS sig
	lmsparams, err := typecode.LmsParams()
	if err != nil {
		return LmsSignature{}, err
	}
	var height = lmsparams.H
	m := lmsparams.M
	var start = otsigmax + 4

	// Explicitly check that q < 2^H
	if q >= (1 << height) {
		return LmsSignature{}, errors.New("LmsSignatureFromBytes(): Internal counter is too high")
	}

	// Read the authentication path
	var path = make([][]byte, lmsparams.H)
	var i uint64
	for i = 0; i < height; i++ {
		end := start + m
		path[i] = b[start:end]
		start += m
	}

	return LmsSignature{
		typecode: typecode,
		q:        q,
		ots:      otsig,
		path:     path,
	}, nil
}

// ToBytes() serializes the signature into a byte string for transmission or storage.
func (sig *LmsSignature) ToBytes() ([]byte, error) {
	var serialized []byte
	var u32_be [4]byte
	typecode, err := sig.typecode.LmsType()
	if err != nil {
		return nil, err
	}
	params, err := typecode.LmsParams()
	if err != nil {
		return nil, err
	}

	// First 4 bytes: q
	binary.BigEndian.PutUint32(u32_be[:], sig.q)
	serialized = append(serialized, u32_be[:]...)

	// Encode the LM-OTS signature next
	// currenly undefined func
	ots_sig, err := sig.ots.ToBytes()
	if err != nil {
		return nil, err
	}

	serialized = append(serialized, ots_sig[:]...)

	// Next 4 bytes: LMS typecode
	binary.BigEndian.PutUint32(u32_be[:], typecode.ToUint32())
	serialized = append(serialized, u32_be[:]...)

	// Next M * H bytes: Path
	height := int(params.H)
	for i := 0; i < height; i++ {
		serialized = append(serialized, sig.path[i]...)
	}

	return serialized, nil
}
