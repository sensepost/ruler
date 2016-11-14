package rpchttp

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/sensepost/ruler/utils"
)

//RTSHeader structure for unmarshal
type RTSHeader struct {
	Version          uint8 //05
	VersionMinor     uint8 //00
	Type             uint8
	PFCFlags         uint8
	PackedDrep       uint32
	FragLen          uint16
	AuthLen          uint16
	CallID           uint32
	Flags            uint16
	NumberOfCommands uint16
}

//RTSSec the security trailer
//this is going to be 0x00000010 for all of our requests
type RTSSec struct {
	Sec uint32
}

//BindPDU struct
type BindPDU struct {
	Header RTSHeader
	PDU    []byte
	Sec    RTSSec
}

//CONNA1 struct for initial connection
type CONNA1 struct {
	Header               RTSHeader
	Version              []byte //8 bytes
	VirtualConnectCookie Cookie
	OutChannelCookie     Cookie
	ReceiveWindowSize    []byte //8 bytes
}

//CONNB1 struct for initial connection
type CONNB1 struct {
	Header               RTSHeader
	Version              []byte //8 bytes
	VirtualConnectCookie Cookie
	InChannelCookie      Cookie
	ChannelLifetime      ChannelLifetime
	ClientKeepAlive      ClientKeepalive
	AssociatonGroupID    AssociationGroupId
}

//RTSRequest an RTSRequest
type RTSRequest struct {
	Header   RTSHeader
	DontKnow []byte //8 bytes
	Cookie   []byte //16-byte cookie
	Data     []byte //our MAPI request goes here
	Sec      uint32
}

//RTSPing an RTSPing message keeping the channel alive
type RTSPing struct {
	Header RTSHeader
	Sec    RTSSec
}

type Cookie struct {
	CommandType uint32 //always going to be 03
	Cookie      []byte //16 byte
}

type AssociationGroupId struct {
	CommandType        uint32
	AssociationGroupID []byte //16 byte
}

type ChannelLifetime struct {
	CommandType     uint32 //always 04
	ChannelLifetime uint32 //range of 128kb to 2 Gb
}

type ClientKeepalive struct {
	CommandType     uint32 //always 05
	ClientKeepalive uint32 //range of 128kb to 2 Gb
}

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

//Bind function Creates a Bind Packet
func Bind() BindPDU {
	bind := BindPDU{}
	header := RTSHeader{Version: 0x05, VersionMinor: 0, Type: DCERPC_PKT_BIND, PFCFlags: 0x13, AuthLen: 0, CallID: 2}

	header.FragLen = 0x0074 //calculate
	bind.Header = header
	//Generate session cookie
	bind.PDU = []byte{0xf8, 0x0f, 0xf8, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xdb, 0xf1, 0xa4, 0x47, 0xca, 0x67, 0x10, 0xb3, 0x1f, 0x00, 0xdd, 0x01, 0x06, 0x62, 0xda, 0x00, 0x00, 0x51, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xdb, 0xf1, 0xa4, 0x47, 0xca, 0x67, 0x10, 0xb3, 0x1f, 0x00, 0xdd, 0x01, 0x06, 0x62, 0xda, 0x00, 0x00, 0x51, 0x00, 0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	//unknown PDU data here
	bind.Sec = RTSSec{0x00000010}
	return bind
}

func ConnA1(channelCookie []byte) CONNA1 {
	conna1 := CONNA1{}
	header := RTSHeader{Version: 0x05, VersionMinor: 0, Type: DCERPC_PKT_RTS, PFCFlags: 0x03, AuthLen: 0, CallID: 0}
	header.PackedDrep = 16
	header.Flags = RTS_FLAG_NONE
	header.NumberOfCommands = 4
	conna1.Header = header
	conna1.Version = []byte{0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	conna1.VirtualConnectCookie = Cookie{3, channelCookie}
	conna1.OutChannelCookie = Cookie{3, CookieGen()}
	conna1.ReceiveWindowSize = []byte{00, 00, 00, 00, 00, 00, 00, 01, 00}
	conna1.Header.FragLen = uint16(len(conna1.Marshal()) - 1)
	return conna1
}

func ConnB1() CONNB1 {
	connb1 := CONNB1{}
	header := RTSHeader{Version: 0x05, VersionMinor: 0, Type: DCERPC_PKT_RTS, PFCFlags: 0x03, AuthLen: 0, CallID: 0}
	header.Flags = RTS_FLAG_NONE
	header.PackedDrep = 16
	header.NumberOfCommands = 6
	connb1.Header = header
	connb1.Version = []byte{0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	connb1.VirtualConnectCookie = Cookie{3, CookieGen()}
	connb1.InChannelCookie = Cookie{3, CookieGen()}
	connb1.ChannelLifetime = ChannelLifetime{4, 1073741824}
	connb1.ClientKeepAlive = ClientKeepalive{5, 300000}
	connb1.AssociatonGroupID = AssociationGroupId{12, CookieGen()}
	connb1.Header.FragLen = uint16(len(connb1.Marshal()))
	return connb1
}

//Ping function creates a Ping Packet
func Ping() RTSPing {
	ping := RTSPing{}
	ping.Header = RTSHeader{Version: 0x05, VersionMinor: 0, Type: DCERPC_PKT_RTS, PFCFlags: 0x03, AuthLen: 0, CallID: 0}
	ping.Header.FragLen = 20
	ping.Sec = RTSSec{0x00000010}
	return ping
}

//Marshal turn RTSPing into Bytes
func (rtsPing RTSPing) Marshal() []byte {
	return utils.BodyToBytes(rtsPing)
}

//Marshal turn Bind into Bytes
func (rtsBind BindPDU) Marshal() []byte {
	return utils.BodyToBytes(rtsBind)
}

//Marshal turn RTSRequest into Bytes
func (rtsRequest RTSRequest) Marshal() []byte {
	return utils.BodyToBytes(rtsRequest)
}

func (connA1Request CONNA1) Marshal() []byte {
	return utils.BodyToBytes(connA1Request)
}

func (connB1Request CONNB1) Marshal() []byte {
	return utils.BodyToBytes(connB1Request)
}
