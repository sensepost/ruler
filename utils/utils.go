package utils

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"reflect"
)

var (
	put32     = binary.LittleEndian.PutUint32
	put16     = binary.LittleEndian.PutUint16
	EncBase64 = base64.StdEncoding.EncodeToString
	DecBase64 = base64.StdEncoding.DecodeString
)

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

//UTF16BE func to encode strings for the CRuleElement
func UTF16BE(str string, trail int) []byte {
	bt := make([]byte, (len(str) * 2))
	cnt := 0
	for _, v := range str {
		bt[cnt] = byte(v)
		cnt++
		bt[cnt] = 0x00
		cnt++
	}
	if trail == 1 {
		bt = append(bt, []byte{0x01}...)
	}
	byteNum := new(bytes.Buffer)
	binary.Write(byteNum, binary.BigEndian, uint16(len(bt)/2))

	bt = append(byteNum.Bytes(), bt...)
	return bt
}

func DecodeUint32(num []byte) uint32 {
	var number uint32
	bf := bytes.NewReader(num)
	binary.Read(bf, binary.LittleEndian, &number)
	return number
}
func DecodeUint16(num []byte) uint16 {
	var number uint16
	bf := bytes.NewReader(num)
	binary.Read(bf, binary.LittleEndian, &number)
	return number
}

func DecodeUint8(num []byte) uint8 {
	var number uint8
	bf := bytes.NewReader(num)
	binary.Read(bf, binary.LittleEndian, &number)
	return number
}
func EncodeNum(v interface{}) []byte {
	byteNum := new(bytes.Buffer)
	binary.Write(byteNum, binary.LittleEndian, v)
	return byteNum.Bytes()
}

//BodyToBytes func
func BodyToBytes(DataStruct interface{}) []byte {
	dumped := []byte{}
	v := reflect.ValueOf(DataStruct)
	var value []byte

	//check if we have a slice of structs
	if reflect.TypeOf(DataStruct).Kind() == reflect.Slice {
		for i := 0; i < v.Len(); i++ {
			if v.Index(i).Kind() == reflect.Uint8 || v.Index(i).Kind() == reflect.Uint16 || v.Index(i).Kind() == reflect.Uint32 {
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
			if v.Field(i).Kind() == reflect.Uint8 || v.Field(i).Kind() == reflect.Uint16 || v.Field(i).Kind() == reflect.Uint32 {
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

func ReadUint32(pos int, buff []byte) (uint32, int) {
	return DecodeUint32(buff[pos : pos+4]), pos + 4
}

func ReadUint16(pos int, buff []byte) (uint16, int) {
	return DecodeUint16(buff[pos : pos+2]), pos + 2
}
func ReadUint8(pos int, buff []byte) (uint8, int) {
	return DecodeUint8(buff[pos : pos+2]), pos + 2
}

func ReadBytes(pos, count int, buff []byte) ([]byte, int) {
	return buff[pos : pos+count], pos + count
}

func ReadByte(pos int, buff []byte) (byte, int) {
	return buff[pos : pos+1][0], pos + 1
}

func ReadUnicodeString(pos int, buff []byte) ([]byte, int) {
	//stupid hack as using bufio and ReadString(byte) would terminate too early
	//would terminate on 0x00 instead of 0x0000
	index := bytes.Index(buff[pos:], []byte{0x00, 0x00})
	str := buff[pos : pos+index]
	return []byte(str), pos + index + 2
}

func ReadASCIIString(pos int, buff []byte) ([]byte, int) {
	bf := bytes.NewBuffer(buff[pos:])
	str, _ := bf.ReadString(0x00)
	return []byte(str), pos + len(str)
}

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
