// Package common contains some data types and utilities used throughout
// the lms and ots packages.
//
// This file defines values that should be treated as constants.
package common

const ID_LEN uint64 = 16

// arrays cannot be constant in go
// please never change these values
var D_PBLC = [2]uint8{0x80, 0x80}
var D_MESG = [2]uint8{0x81, 0x81}
var D_LEAF = [2]uint8{0x82, 0x82}
var D_INTR = [2]uint8{0x83, 0x83}
