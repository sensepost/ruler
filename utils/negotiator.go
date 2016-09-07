package utils

//Forked from https://github.com/vadimi/go-http-ntlm
//All credits go to them
//Used under MIT License -- see LICENSE for details
//Modified code -- negotiateSP function

import (
	"encoding/base64"
	"encoding/binary"
)

const (
	negotiateUnicode    = 0x0001 // Text strings are in unicode
	negotiateOEM        = 0x0002 // Text strings are in OEM
	requestTarget       = 0x0004 // Server return its auth realm
	negotiateSign       = 0x0010 // Request signature capability
	negotiateSeal       = 0x0020 // Request confidentiality
	negotiateLMKey      = 0x0080 // Generate session key
	negotiateNTLM       = 0x0200 // NTLM authentication
	negotiateLocalCall  = 0x4000 // client/server on same machine
	negotiateAlwaysSign = 0x8000 // Sign for all security levels
)

var (
	put32     = binary.LittleEndian.PutUint32
	put16     = binary.LittleEndian.PutUint16
	EncBase64 = base64.StdEncoding.EncodeToString
	DecBase64 = base64.StdEncoding.DecodeString
)

//modified function that works with an edge-case server
func NegotiateSP() []byte {
	ret := make([]byte, 32)
	flags := negotiateAlwaysSign | negotiateNTLM | requestTarget | negotiateOEM

	copy(ret, []byte("NTLMSSP\x00")) // protocol
	put32(ret[8:], 1)                // type
	put32(ret[12:], uint32(flags))   // flags
	ret[14] = 8

	return ret
}

// generates NTLM Negotiate type-1 message
// for details see http://www.innovation.ch/personal/ronald/ntlm.html
func negotiate() []byte {
	ret := make([]byte, 32)
	flags := negotiateAlwaysSign | negotiateNTLM | requestTarget | negotiateOEM | negotiateUnicode

	copy(ret, []byte("NTLMSSP\x00")) // protocol
	put32(ret[8:], 1)                // type
	put32(ret[12:], uint32(flags))   // flags
	put16(ret[16:], 0)               // NT domain name length
	put16(ret[18:], 0)               // NT domain name max length
	put32(ret[20:], 0)               // NT domain name offset
	put16(ret[24:], 0)               // local workstation name length
	put16(ret[26:], 0)               // local workstation name max length
	put32(ret[28:], 0)               // local workstation name offset
	put16(ret[32:], 0)               // unknown name length
	put16(ret[34:], 0)               // ...
	put16(ret[36:], 0x30)            // unknown offset
	put16(ret[38:], 0)               // unknown name length
	put16(ret[40:], 0)               // ...
	put16(ret[42:], 0x30)            // unknown offset

	return ret
}
