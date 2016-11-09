package rpchttp

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

//BindPDU struct
type BindPDU struct {
	Header RTSHeader
	PDU    []byte
}

//RTSRequest an RTSRequest
type RTSRequest struct {
	Header           RTSHeader
	Flags            uint16
	NumberOfCommands uint16
	DontKnow         []byte //8 bytes
	Cookie           []byte //16-byte cookie
	Data             []byte //our MAPI request goes here
}

//Bind function Creates a Bind Packet
func Bind() BindPDU {
	bind := BindPDU{}
	header := RTSHeader{Version: 0x05, VersionMinor: 0, Type: DCERPC_PKT_BIND, PFCFlags: 0x03, AuthLen: 0, CallID: 2}
	header.FragLen = 0x0074 //calculate
	bind.Header = header
	//unknown PDU data here
	return bind
}
