package common

import (
	"crypto/sha256"
	"errors"
	"hash"
)

// ID is a fixed-legnth []byte used in LM-OTS and LM-OTS
type ID [ID_LEN]byte

type window uint8

const (
	WINDOW_W1 window = 1 << iota
	WINDOW_W2
	WINDOW_W4
	WINDOW_W8
)

// ByteWindow is the representation of bytes used in calculating LM-OTS signatures
type ByteWindow interface {
	Window() window
	Mask() uint8
}

// Return the actual window value
func (w window) Window() window {
	return w
}

// Return a bit mask (uint8) to bitwise AND with some value
func (w window) Mask() uint8 {
	switch w {
	case WINDOW_W1:
		return 0x01
	case WINDOW_W2:
		return 0x03
	case WINDOW_W4:
		return 0x0f
	case WINDOW_W8:
		return 0xff
	default:
		panic("invalid window")
	}
}

type lms_type_code uint32

const (
	LMS_RESERVED lms_type_code = iota
	LMOTS_SHA256_N32_W1
	LMOTS_SHA256_N32_W2
	LMOTS_SHA256_N32_W4
	LMOTS_SHA256_N32_W8
	LMS_SHA256_M32_H5
	LMS_SHA256_M32_H10
	LMS_SHA256_M32_H15
	LMS_SHA256_M32_H20
	LMS_SHA256_M32_H25
)

// LmsAlgorithmType represents a specific instance of LMS
type LmsAlgorithmType interface {
	LmsType() (lms_type_code, error)
	LmsParams() LmsParam
}

// LmsOtsAlgorithmType represents a specific instance of LM-OTS
type LmsOtsAlgorithmType interface {
	LmsOtsType() (lms_type_code, error)
	Params() LmsOtsParam
}

// Hasher represents a streaming hash function
type Hasher interface {
	New() hash.Hash
}

type Sha256Hasher struct{}

func (_ Sha256Hasher) New() hash.Hash {
	return sha256.New()
}

// LmsParam represents the parameters for a given instance of the LMS algorithm
type LmsParam struct {
	Hash Hasher // Used to return an instance of a hash function in streaming mode
	M    uint64 // number of bytes associated with each node
	H    uint64 // height of the tree
}

type LmsOtsParam struct {
	H       Hasher     // Used for hashing
	N       uint64     // number of bytes of the output of H
	W       ByteWindow // width (in bits) of Winternitz coefficients
	P       uint64     // number of N-byte elements that make up the signature
	LS      uint64     // left-shift used in checksum calculation
	SIG_LEN uint64     // total byte length for a valid signature
}

// Returns a lms_type_code, given a uint32 of the same value
func Uint32ToLmsType(x uint32) lms_type_code {
	return lms_type_code(x)
}

// Returns a uint32 of the same value as the lms_type_code
func (x lms_type_code) ToUint32() uint32 {
	return uint32(x)
}

// Returns a lms_type_code if within a valid range for LMS; otherwise, an error
func (x lms_type_code) LmsType() (lms_type_code, error) {
	if x >= LMS_SHA256_M32_H5 && x <= LMS_SHA256_M32_H25 {
		return x, nil
	} else {
		return x, errors.New("LmsType(): invalid type code")
	}
}

// Returns the expected signature length for an LMS type, given an associated LM-OTS type
func (x lms_type_code) LmsSigLength(otstc lms_type_code) uint64 {
	if x >= LMS_SHA256_M32_H5 && x <= LMS_SHA256_M32_H25 {
		params := x.LmsParams()
		return uint64(4 + 4 + otstc.LmsOtsSigLength() + (params.H * params.M))
	} else {
		panic("LmsSigLength(): invalid type code")
	}
}

// Returns a lms_type_code if within a valid range for LM-OTS; otherwise, an error
func (x lms_type_code) LmsOtsType() (lms_type_code, error) {
	if x >= LMOTS_SHA256_N32_W1 && x <= LMOTS_SHA256_N32_W8 {
		return x, nil
	} else {
		return x, errors.New("LmsOtsType(): invalid type code")
	}
}

// Returns the expected byte length of a given LM-OTS signature algorithm
func (x lms_type_code) LmsOtsSigLength() uint64 {
	if x >= LMOTS_SHA256_N32_W1 && x <= LMOTS_SHA256_N32_W8 {
		return x.Params().SIG_LEN
	} else {
		panic("LmsOtsSigLength(): invalid type code")
	}
}

// Returns a LmsParam corresponding to the lms_type_code, x
func (x lms_type_code) LmsParams() LmsParam {
	switch x {
	case LMS_SHA256_M32_H5:
		return LmsParam{
			Hash: Sha256Hasher{},
			M:    32,
			H:    5,
		}
	case LMS_SHA256_M32_H10:
		return LmsParam{
			Hash: Sha256Hasher{},
			M:    32,
			H:    10,
		}
	case LMS_SHA256_M32_H15:
		return LmsParam{
			Hash: Sha256Hasher{},
			M:    32,
			H:    15,
		}
	case LMS_SHA256_M32_H20:
		return LmsParam{
			Hash: Sha256Hasher{},
			M:    32,
			H:    20,
		}
	case LMS_SHA256_M32_H25:
		return LmsParam{
			Hash: Sha256Hasher{},
			M:    32,
			H:    25,
		}
	default:
		panic("LmsParams(): invalid type code")
	}
}

// Returns a LmsOtsParam corresponding to the lms_type_code, x
func (x lms_type_code) Params() LmsOtsParam {
	switch x {
	case LMOTS_SHA256_N32_W1:
		return LmsOtsParam{
			H:       Sha256Hasher{},
			N:       sha256.Size,
			W:       WINDOW_W1,
			P:       265,
			LS:      7,
			SIG_LEN: 8516,
		}
	case LMOTS_SHA256_N32_W2:
		return LmsOtsParam{
			H:       Sha256Hasher{},
			N:       sha256.Size,
			W:       WINDOW_W2,
			P:       133,
			LS:      6,
			SIG_LEN: 4292,
		}
	case LMOTS_SHA256_N32_W4:
		return LmsOtsParam{
			H:       Sha256Hasher{},
			N:       sha256.Size,
			W:       WINDOW_W4,
			P:       67,
			LS:      4,
			SIG_LEN: 2180,
		}
	case LMOTS_SHA256_N32_W8:
		return LmsOtsParam{
			H:       Sha256Hasher{},
			N:       sha256.Size,
			W:       WINDOW_W8,
			P:       34,
			LS:      0,
			SIG_LEN: 1124,
		}
	default:
		panic("Params(): invalid type code")
	}
}
