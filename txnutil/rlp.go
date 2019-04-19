package txnutil

import (
	"bytes"
	_ "encoding/binary"
	"errors"
	"fmt"
	"io"
	_ "log"
	_ "math"
	"math/big"
)

type RlpEncoder struct {
	rlpData []byte
}

func NewRlpEncoder() *RlpEncoder {
	encoder := &RlpEncoder{}

	return encoder
}
func (coder *RlpEncoder) EncodeData(rlpData interface{}) []byte {
	return Encode(rlpData)
}

/*
func FromBin(data []byte) uint64 {
	if len(data) == 0 {
		return 0
	}

	return FromBin(data[:len(data)-1])*256 + uint64(data[len(data)-1])
}
*/

const (
	RlpEmptyList = 0x80
	RlpEmptyStr  = 0x40
)

func Char(c []byte) int {
	if len(c) > 0 {
		return int(c[0])
	}

	return 0
}

func DecodeWithReader(reader *bytes.Buffer) interface{} {
	var slice []interface{}

	// Read the next byte
	char := Char(reader.Next(1))
	switch {
	case char == 0:
		return nil
	case char <= 0x7c:
		return char

	case char <= 0xb7:
		return reader.Next(int(char - 0x80))

	case char <= 0xbf:
		buff := bytes.NewReader(reader.Next(int(char - 0xb8)))
		length := ReadVarint(buff)

		return reader.Next(int(length))

	case char <= 0xf7:
		length := int(char - 0xc0)
		for i := 0; i < length; i++ {
			obj := DecodeWithReader(reader)
			if obj != nil {
				slice = append(slice, obj)
			} else {
				break
			}
		}

		return slice

	}

	return slice
}

// TODO Use a bytes.Buffer instead of a raw byte slice.
// Cleaner code, and use draining instead of seeking the next bytes to read
func Decode(data []byte, pos uint64) (interface{}, uint64) {
	var slice []interface{}
	char := int(data[pos])
	switch {
	case char <= 0x7f:
		return data[pos], pos + 1

	case char <= 0xb7:
		b := uint64(data[pos]) - 0x80

		return data[pos+1 : pos+1+b], pos + 1 + b

	case char <= 0xbf:
		b := uint64(data[pos]) - 0xb7

		b2, _ := readSize(data[pos+1:], data[pos]-0xb7)

		return data[pos+1+b : pos+1+b+b2], pos + 1 + b + b2

	case char <= 0xf7:
		b := uint64(data[pos]) - 0xc0
		prevPos := pos
		pos++
		for i := uint64(0); i < b; {
			var obj interface{}

			// Get the next item in the data list and append it
			obj, prevPos = Decode(data, pos)
			slice = append(slice, obj)

			// Increment i by the amount bytes read in the previous
			// read
			i += (prevPos - pos)
			pos = prevPos
		}
		return slice, pos

	case char <= 0xff:
		l := uint64(data[pos]) - 0xf7
		b, _ := readSize(data[pos+1:], data[pos]-0xf7)
		pos = pos + l + 1

		prevPos := b
		for i := uint64(0); i < uint64(b); {
			var obj interface{}

			obj, prevPos = Decode(data, pos)
			slice = append(slice, obj)

			i += (prevPos - pos)
			pos = prevPos
		}
		return slice, pos

	default:
		panic(fmt.Sprintf("byte not supported: %q", char))
	}

	return slice, 0
}

var (
	directRlp = big.NewInt(0x7f)
	numberRlp = big.NewInt(0xb7)
	zeroRlp   = big.NewInt(0x0)
)

func Encode(object interface{}) []byte {

	// buf := make([]byte, 0, 256)
	// buff := bytes.NewBuffer(buf)
	var buff bytes.Buffer

	if object != nil {
		switch t := object.(type) {
		case *Value:
			buff.Write(Encode(t.Raw()))
		// Code dup :-/
		case int:
			buff.Write(Encode(big.NewInt(int64(t))))
		case uint:
			buff.Write(Encode(big.NewInt(int64(t))))
		case int8:
			buff.Write(Encode(big.NewInt(int64(t))))
		case int16:
			buff.Write(Encode(big.NewInt(int64(t))))
		case int32:
			buff.Write(Encode(big.NewInt(int64(t))))
		case int64:
			buff.Write(Encode(big.NewInt(int64(t))))
		case uint16:
			buff.Write(Encode(big.NewInt(int64(t))))
		case uint32:
			buff.Write(Encode(big.NewInt(int64(t))))
		case uint64:
			buff.Write(Encode(big.NewInt(int64(t))))
		case byte:
			buff.Write(Encode(big.NewInt(int64(t))))
		case *big.Int:
			buff.Write(Encode(t.Bytes()))
		case []byte:
			if len(t) == 1 && t[0] <= 0x7f {
				buff.Write(t)
			} else if len(t) < 56 {
				buff.WriteByte(byte(len(t) + 0x80))
				buff.Write(t)
			} else {
				b := big.NewInt(int64(len(t)))
				buff.WriteByte(byte(len(b.Bytes()) + 0xb7))
				buff.Write(b.Bytes())
				buff.Write(t)
			}
		case string:
			buff.Write(Encode([]byte(t)))
		case []interface{}:
			// Inline function for writing the slice header
			WriteSliceHeader := func(length int) {
				if length < 56 {
					buff.WriteByte(byte(length + 0xc0))
				} else {
					b := big.NewInt(int64(length))
					buff.WriteByte(byte(len(b.Bytes()) + 0xf7))
					buff.Write(b.Bytes())
				}
			}

			var b bytes.Buffer
			for _, val := range t {
				b.Write(Encode(val))
			}
			WriteSliceHeader(len(b.Bytes()))
			buff.Write(b.Bytes())
		}
	} else {
		// Empty list for nil
		buff.WriteByte(0xc0)
	}

	return buff.Bytes()
}
func readSize(b []byte, slen byte) (uint64, error) {
	if int(slen) > len(b) {
		return 0, io.ErrUnexpectedEOF
	}
	var s uint64
	switch slen {
	case 1:
		s = uint64(b[0])
	case 2:
		s = uint64(b[0])<<8 | uint64(b[1])
	case 3:
		s = uint64(b[0])<<16 | uint64(b[1])<<8 | uint64(b[2])
	case 4:
		s = uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
	case 5:
		s = uint64(b[0])<<32 | uint64(b[1])<<24 | uint64(b[2])<<16 | uint64(b[3])<<8 | uint64(b[4])
	case 6:
		s = uint64(b[0])<<40 | uint64(b[1])<<32 | uint64(b[2])<<24 | uint64(b[3])<<16 | uint64(b[4])<<8 | uint64(b[5])
	case 7:
		s = uint64(b[0])<<48 | uint64(b[1])<<40 | uint64(b[2])<<32 | uint64(b[3])<<24 | uint64(b[4])<<16 | uint64(b[5])<<8 | uint64(b[6])
	case 8:
		s = uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 | uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	}
	// Reject sizes < 56 (shouldn't have separate size) and sizes with
	// leading zero bytes.
	if s < 56 || b[0] == 0 {
		return 0, errors.New("rlp: non-canonical size information")
	}
	return s, nil
}
