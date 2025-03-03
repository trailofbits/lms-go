// Package common contains some data types and utilities used throughout
// the lms and ots packages.
//
// This file includes some utility functions.
package common

import (
	"encoding/binary"
	"hash"
)

// Returns a []byte representing the Winternitz coefficients of x for a given window, w
func Coefs(x []byte, w ByteWindow) []uint8 {
	mask := w.Mask()
	win := uint64(w.Window())

	entries_per_byte := 8 / win

	n := entries_per_byte * uint64(len(x))
	res := make([]uint8, n)

	for i := uint64(0); i < n; i++ {
		entry := i / entries_per_byte
		offset := i % entries_per_byte
		shift := 8 - win - offset*win
		res[i] = (x[entry] >> shift) & mask
	}

	return res
}

// Returns a checksum calculated over a slice of Winternitz coefficients
func Cksm(coefs []uint8, w ByteWindow, LS uint64) uint16 {
	var sum uint16 = 0
	win := int(w.Window())

	for i := 0; i < len(coefs); i++ {
		sum += (1 << win) - 1 - uint16(coefs[i])
	}

	return sum << int(LS)
}

// expands a message into the winternitz coefficients of the message and its checksum
// returns a slice of length P
func Expand(msg []byte, mode LmsOtsAlgorithmType) ([]uint8, error) {
	params, err := mode.Params()
	if err != nil {
		return nil, err
	}
	res := Coefs(msg, params.W)
	var cksm [2]byte
	binary.BigEndian.PutUint16(cksm[:], Cksm(res, params.W, params.LS))

	res = append(res, Coefs(cksm[:], params.W)...)

	return res[:params.P], nil
}

// HashWrite wraps h.Write with a panic.
func HashWrite(h hash.Hash, x []byte) {
	_, err := h.Write(x)
	if err != nil {
		panic("hash.Hash.Write never errors")
	}
}

// HashSum wraps Hash.Sum, returning the n leftmost bytes.
// Panics if n is larger than the length of the hash output.
func HashSum(h hash.Hash, n uint64) []byte {
	return h.Sum(nil)[:n]
}
