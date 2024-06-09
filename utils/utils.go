package utils

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"math/rand"
	"os"
	"reflect"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

var (
	put32 = binary.LittleEndian.PutUint32
	put16 = binary.LittleEndian.PutUint16
	//EncBase64 wrapper for encoding to base64
	EncBase64 = base64.StdEncoding.EncodeToString
	//DecBase64 wrapper for decoding from base64
	DecBase64 = base64.StdEncoding.DecodeString
)

// ReadFile returns the contents of a file at 'path'
func ReadFile(path string) ([]byte, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// CookieGen creates a 16byte UUID
func CookieGen() []byte {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("Error: ", err)
		return nil
	}
	//fmt.Printf("%X%X%X%X%X\n", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	return b
}

// COUNT returns the uint16 byte stream of an int. This is required for PtypBinary
func COUNT(val int) []byte {
	return EncodeNum(uint16(val))
}

// FromUnicode read unicode and convert to byte array
func FromUnicode(uni []byte) string {
	st := ""
	for _, k := range uni {
		if k != 0x00 {
			st += string(k)
		}
	}
	return st
}

// UniString converts a string into a unicode string byte array
func UniString(str string) []byte {
	bt := make([]byte, (len(str) * 2))
	cnt := 0
	for _, v := range str {
		bt[cnt] = byte(v)
		cnt++
		bt[cnt] = 0x00
		cnt++
	}
	bt = append(bt, []byte{0x00, 0x00}...)
	return bt
}

// UTF16BE func to encode strings for the CRuleElement
func UTF16BE(str string) []byte {
	bt := make([]byte, (len(str) * 2))
	cnt := 0
	for _, v := range str {
		bt[cnt] = byte(v)
		cnt++
		bt[cnt] = 0x00
		cnt++
	}

	byteNum := new(bytes.Buffer)
	binary.Write(byteNum, binary.BigEndian, uint16(len(bt)/2))

	bt = append(byteNum.Bytes(), bt...)
	return bt
}

// ToBinary takes a string and hexlyfies it
func ToBinary(str string) []byte {
	src := []byte(str)
	//binary requires length
	dst := append(COUNT(len(src)), src...)
	return dst
}

// DecodeInt64 decode 8 byte value into int64
func DecodeInt64(num []byte) int64 {
	var number int64
	bf := bytes.NewReader(num)
	binary.Read(bf, binary.BigEndian, &number)
	return number
}

// DecodeUint64 decode 4 byte value into uint32
func DecodeUint64(num []byte) uint64 {
	var number uint64
	bf := bytes.NewReader(num)
	binary.Read(bf, binary.LittleEndian, &number)
	return number
}

// DecodeUint32 decode 4 byte value into uint32
func DecodeUint32(num []byte) uint32 {
	var number uint32
	bf := bytes.NewReader(num)
	binary.Read(bf, binary.LittleEndian, &number)
	return number
}

// DecodeUint16 decode 2 byte value into uint16
func DecodeUint16(num []byte) uint16 {
	var number uint16
	bf := bytes.NewReader(num)
	binary.Read(bf, binary.LittleEndian, &number)
	return number
}

// DecodeUint8 decode 1 byte value into uint8
func DecodeUint8(num []byte) uint8 {
	var number uint8
	bf := bytes.NewReader(num)
	binary.Read(bf, binary.LittleEndian, &number)
	return number
}

// EncodeNum encode a number as a byte array
func EncodeNum(v interface{}) []byte {
	byteNum := new(bytes.Buffer)
	binary.Write(byteNum, binary.LittleEndian, v)
	return byteNum.Bytes()
}

// EncodeNumBE encode a number in big endian as a byte array
func EncodeNumBE(v interface{}) []byte {
	byteNum := new(bytes.Buffer)
	binary.Write(byteNum, binary.BigEndian, v)
	return byteNum.Bytes()
}

// BodyToBytes func
func BodyToBytes(DataStruct interface{}) []byte {
	dumped := []byte{}
	v := reflect.ValueOf(DataStruct)
	var value []byte

	//check if we have a slice of structs
	if reflect.TypeOf(DataStruct).Kind() == reflect.Slice {
		for i := 0; i < v.Len(); i++ {
			if v.Index(i).Kind() == reflect.Uint8 || v.Index(i).Kind() == reflect.Uint16 || v.Index(i).Kind() == reflect.Uint32 || v.Index(i).Kind() == reflect.Uint64 {
				byteNum := new(bytes.Buffer)
				binary.Write(byteNum, binary.LittleEndian, v.Index(i).Interface())
				dumped = append(dumped, byteNum.Bytes()...)
			} else {
				if v.Index(i).Kind() == reflect.Struct || v.Index(i).Kind() == reflect.Slice || v.Index(i).Kind() == reflect.Interface {
					value = BodyToBytes(v.Index(i).Interface())
				} else {
					value = v.Index(i).Bytes()
				}
				dumped = append(dumped, value...)
			}
		}
	} else {
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).Kind() == reflect.Uint8 || v.Field(i).Kind() == reflect.Uint16 || v.Field(i).Kind() == reflect.Uint32 || v.Field(i).Kind() == reflect.Uint64 {
				byteNum := new(bytes.Buffer)
				binary.Write(byteNum, binary.LittleEndian, v.Field(i).Interface())
				dumped = append(dumped, byteNum.Bytes()...)
			} else {
				if v.Field(i).Kind() == reflect.Struct || v.Field(i).Kind() == reflect.Slice || v.Field(i).Kind() == reflect.Interface {
					value = BodyToBytes(v.Field(i).Interface())
				} else {
					fmt.Println(v.Field(i).Kind())
					value = v.Field(i).Bytes()
				}
				dumped = append(dumped, value...)
			}
		}
	}
	return dumped
}

// ReadUint32 read 4 bytes and return as uint32
func ReadUint32(pos int, buff []byte) (uint32, int) {
	return DecodeUint32(buff[pos : pos+4]), pos + 4
}

// ReadUint16 read 2 bytes and return as uint16
func ReadUint16(pos int, buff []byte) (uint16, int) {
	return DecodeUint16(buff[pos : pos+2]), pos + 2
}

// ReadUint8 read 1 byte and return as uint8
func ReadUint8(pos int, buff []byte) (uint8, int) {
	return DecodeUint8(buff[pos : pos+2]), pos + 2
}

// ReadBytes read and return count number o bytes
func ReadBytes(pos, count int, buff []byte) ([]byte, int) {
	return buff[pos : pos+count], pos + count
}

// ReadByte read and return a single byte
func ReadByte(pos int, buff []byte) (byte, int) {
	return buff[pos : pos+1][0], pos + 1
}

// ReadUnicodeString read and return a unicode string
func ReadUnicodeString(pos int, buff []byte) ([]byte, int) {
	//stupid hack as using bufio and ReadString(byte) would terminate too early
	//would terminate on 0x00 instead of 0x0000
	index := bytes.Index(buff[pos:], []byte{0x00, 0x00})
	if index == -1 {
		return nil, 0
	}
	str := buff[pos : pos+index]
	return []byte(str), pos + index + 2
}

// ReadUTF16BE reads the unicode string that the outlook rule file uses
// this basically means there is a length byte that we need to skip over
func ReadUTF16BE(pos int, buff []byte) ([]byte, int) {

	lenb := (buff[pos : pos+1])
	k := int(lenb[0])
	pos += 1 //length byte but we don't really need this
	var str []byte
	if k == 0 {
		str, pos = ReadUnicodeString(pos, buff)
	} else {
		str, pos = ReadBytes(pos, k*2, buff) //
		//pos += 2
	}

	return str, pos
}

// ReadASCIIString returns a string as ascii
func ReadASCIIString(pos int, buff []byte) ([]byte, int) {
	bf := bytes.NewBuffer(buff[pos:])
	str, _ := bf.ReadString(0x00)
	return []byte(str), pos + len(str)
}

// ReadTypedString reads a string as either Unicode or ASCII depending on type value
func ReadTypedString(pos int, buff []byte) ([]byte, int) {
	var t = buff[pos]
	if t == 0 { //no string
		return []byte{}, pos + 1
	}
	if t == 1 {
		return []byte{}, pos + 1
	}
	if t == 3 {
		str, p := ReadASCIIString(pos+1, buff)
		return str, p
	}
	if t == 4 {
		str, p := ReadUnicodeString(pos+1, buff)
		return str, p
	}
	str, _ := ReadBytes(pos+1, 4, buff)
	return str, pos + len(str)
}

// Hash Calculate a 32byte hash
func Hash(s string) uint32 {
	h := fnv.New32()
	h.Write([]byte(s))
	return h.Sum32()
}

// Obfuscate traffic using XOR and the magic byte as specified in RPC docs
func Obfuscate(data []byte) []byte {
	bnew := make([]byte, len(data))
	for k := range data {
		bnew[k] = data[k] ^ 0xA5
	}
	return bnew
}

// GenerateString creates a random string of lenght pcount
func GenerateString(pcount int) string {
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	rand.Seed(time.Now().UTC().UnixNano())

	b := make([]rune, pcount)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

// ReadYml reads the supplied config file, Unmarshals the data into the global config struct.
func ReadYml(yml string) (YamlConfig, error) {
	var config YamlConfig
	data, err := os.ReadFile(yml)
	if err != nil {
		return YamlConfig{}, err
	}
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return YamlConfig{}, err
	}
	return config, err
}

// GUIDToByteArray mimics Guid.ToByteArray Method () from .NET
// The example displays the following output:
//
//	Guid: 35918bc9-196d-40ea-9779-889d79b753f0
//	C9 8B 91 35 6D 19 EA 40 97 79 88 9D 79 B7 53 F0
func GUIDToByteArray(guid string) (array []byte, err error) {
	//get rid of {} if passed in
	guid = strings.Replace(guid, "{", "", 1)
	guid = strings.Replace(guid, "}", "", 1)

	sp := strings.Split(guid, "-") //chunk
	//we should have 5 chunks
	if len(sp) != 5 {
		return nil, fmt.Errorf("Invalid GUID")
	}
	//add first 4 chunks to array in reverse order
	for i := 0; i < 4; i++ {
		chunk, e := hex.DecodeString(sp[i])
		if e != nil {
			return nil, e
		}
		for k := len(chunk) - 1; k >= 0; k-- {
			array = append(array, chunk[k])
		}
	}
	chunk, e := hex.DecodeString(sp[4])
	if e != nil {
		return nil, e
	}
	array = append(array, chunk...)
	return array, nil
}
