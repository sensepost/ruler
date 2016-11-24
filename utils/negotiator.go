package utils

//TODO: Merge this into go-ntlm
//Forked from https://github.com/vadimi/go-http-ntlm
//All credits go to them
//Used under MIT License -- see LICENSE for details
//Modified code -- negotiateSP function

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
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

type Type1Msg struct {
	Protocol []byte // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
	Type     byte   // 0x01

	Flags uint16 // 0xb203

	Domlen    uint16 // domain string length
	Domlen2   uint16 // domain string length
	DomOffset uint16 // domain string offset

	Hostlen    uint16 // host string length
	Hostlen2   uint16 // host string length
	HostOffset uint16 // host string offset (always 0x20)

	Host   []byte // host string (ASCII)
	Domain []byte // domain string (ASCII)
}

//NegotiateSP modified function that works with an edge-case server
func NegotiateSP() []byte {
	ret := make([]byte, 40)
	flags := negotiateAlwaysSign | negotiateNTLM | requestTarget | negotiateOEM | negotiateUnicode

	copy(ret, []byte("NTLMSSP\x00")) // protocol
	put32(ret[8:], 1)                // type
	put32(ret[12:], uint32(flags))   // 0x8297)          //uint32(flags))   // flags
	put16(ret[14:], 0xe208)
	put32(ret[32:], 0x2800000a)
	put32(ret[36:], 0x0f000000)
	return ret
}

func Negotiate(domain string) []byte {
	ret := make([]byte, 32)
	flags := negotiateAlwaysSign | negotiateNTLM | requestTarget | negotiateOEM
	hostname := strings.ToUpper("RULER")

	copy(ret, []byte("NTLMSSP\x00")) // protocol
	put32(ret[8:], 1)                // type
	put32(ret[12:], uint32(flags))   // 0x8297)          //uint32(flags))   // flags
	put16(ret[14:], 0x0000)

	put16(ret[16:], uint16(len(domain)))      //domain name length
	put16(ret[18:], uint16(len(domain)))      //domain name length
	put16(ret[20:], uint16(len(hostname)+32)) //domain name offset
	put16(ret[22:], 0x00)                     //padding
	put16(ret[24:], uint16(len(hostname)))    //hostname length
	put16(ret[26:], uint16(len(hostname)))    //hostname length
	put16(ret[28:], 32)                       //hostname offset

	put16(ret[30:], 0x00) //pad

	ret = append(ret, []byte(hostname)...)
	ret = append(ret, []byte(strings.ToUpper(domain))...)

	return ret
}

// generates NTLM Negotiate type-1 message
// for details see http://www.innovation.ch/personal/ronald/ntlm.html
func negotiate() []byte {
	ret := make([]byte, 46)
	//flags := negotiateAlwaysSign | negotiateNTLM | requestTarget | negotiateOEM

	copy(ret, []byte("NTLMSSP\x00")) // protocol
	put32(ret[8:], 1)                // type
	put32(ret[12:], 0x0782)          //uint32(flags))   // flags
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
