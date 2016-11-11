package rpchttp

import "github.com/sensepost/ruler/utils"

//RTSHeader structure for unmarshal
type RTSHeader struct {
	Version      uint8 //05
	VersionMinor uint8 //00
	Type         uint8
	PFCFlags     uint8
	PackedDrep   uint32
	FragLen      uint16
	AuthLen      uint16
	CallID       uint32
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

//RTSRequest an RTSRequest
type RTSRequest struct {
	Header           RTSHeader
	Flags            uint16
	NumberOfCommands uint16
	DontKnow         []byte //8 bytes
	Cookie           []byte //16-byte cookie
	Data             []byte //our MAPI request goes here
	//Sec              RTSSec
}

//RTSPing an RTSPing message keeping the channel alive
type RTSPing struct {
	Header RTSHeader
	Sec    RTSSec
}

//Bind function Creates a Bind Packet
func Bind() BindPDU {
	bind := BindPDU{}
	header := RTSHeader{Version: 0x05, VersionMinor: 0, Type: DCERPC_PKT_BIND, PFCFlags: 0x03, AuthLen: 0, CallID: 2}
	header.FragLen = 0x0074 //calculate
	bind.Header = header
	bind.PDU = []byte{0xf8, 0x0f, 0xf8, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xdb, 0xf1, 0xa4, 0x47, 0xca, 0x67, 0x10, 0xb3, 0x1f, 0x00, 0xdd, 0x01, 0x06, 0x62, 0xda, 0x00, 0x00, 0x51, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xdb, 0xf1, 0xa4, 0x47, 0xca, 0x67, 0x10, 0xb3, 0x1f, 0x00, 0xdd, 0x01, 0x06, 0x62, 0xda, 0x00, 0x00, 0x51, 0x00, 0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	//unknown PDU data here
	bind.Sec = RTSSec{0x00000810}
	return bind
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
