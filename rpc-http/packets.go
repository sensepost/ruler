package rpchttp

import (
	"bytes"
	"fmt"
	"math/rand"
	"time"

	"github.com/sensepost/ruler/utils"
	"github.com/staaldraad/go-ntlm/ntlm"
)

// RTSHeader structure for unmarshal
type RTSHeader struct {
	Version      uint8 //05
	VersionMinor uint8 //00
	Type         uint8
	PFCFlags     uint8
	PackedDrep   uint32
	FragLen      uint16
	AuthLen      uint16
	CallID       uint32
	//Flags            uint16
	//NumberOfCommands uint16
}

// RTSSec the security trailer
// this is going to be 0x00000010 for all of our requests
type RTSSec struct {
	AuthType   uint8
	AuthLevel  uint8
	AuthPadLen uint8
	AuthRsvrd  uint8
	AuthCTX    uint32
}

// BindPDU struct
type BindPDU struct {
	Header             RTSHeader
	MaxFrag            uint16
	MaxRecvFrag        uint16
	AssociationGroupID uint32
	CtxNum             uint32 //2
	CtxItems           []byte
	SecTrailer         []byte
	AuthData           []byte
}

// Auth3Request struct
type Auth3Request struct {
	Header      RTSHeader
	MaxFrag     uint16
	MaxRecvFrag uint16
	//Pad         uint32
	SecTrailer []byte
	AuthData   []byte
}

// CONNA1 struct for initial connection
type CONNA1 struct {
	Header               RTSHeader
	Flags                uint16
	NumberOfCommands     uint16
	Version              []byte //8 bytes
	VirtualConnectCookie Cookie
	OutChannelCookie     Cookie
	ReceiveWindowSize    []byte //8 bytes
}

// CONNB1 struct for initial connection
type CONNB1 struct {
	Header               RTSHeader
	Flags                uint16
	NumberOfCommands     uint16
	Version              []byte //8 bytes
	VirtualConnectCookie Cookie
	InChannelCookie      Cookie
	ChannelLifetime      ChannelLifetime
	ClientKeepAlive      ClientKeepalive
	AssociatonGroupID    AssociationGroupID
}

// RTSRequest an RTSRequest
type RTSRequest struct {
	Header  RTSHeader
	MaxFrag uint16
	MaxRecv uint16
	Command []byte //8-byte
	PduData []byte //PDUData
	//	ContextHandle []byte //16-byte cookie
	//	Data          []byte //our MAPI request goes here
	//RPC Parts
	//	CbAuxIn uint32
	//	AuxOut  uint32
	SecTrailer []byte
	AuthData   []byte
}

type PDUData struct {
	ContextHandle []byte //16-byte cookie
	Data          []byte
	CbAuxIn       uint32
	AuxOut        uint32
}

// ConnectExRequest our connection request
type ConnectExRequest struct {
	Header        RTSHeader
	MaxFrag       uint16
	MaxRecv       uint16
	Version       []byte //8-byte
	ContextHandle []byte //16-byte cookie
	Data          []byte //our MAPI request goes here
	AuxBufLen     uint32
	RgbAuxIn      []byte
	CbAuxIn       uint32
	AuxOut        uint32
}

// RPCHeader common fields
type RPCHeader struct {
	Version    uint16 //always 0x0000
	Flags      uint16 //0x0001 Compressed, 0x0002 XorMagic, 0x0004 Last
	Size       uint16
	SizeActual uint16 //Compressed size (if 0x0001 set)
}

// RPCResponse to hold the data from our response
type RPCResponse struct {
	Header     RTSHeader
	PDU        []byte
	SecTrailer []byte
	Body       []byte
	AutData    []byte
}

// CTX item used in Bind
type CTX struct {
	ContextID      uint16
	TransItems     uint8
	Pad            uint8
	AbstractSyntax []byte //20 bytes
	TransferSyntax []byte //20 bytes
}

// AUXBuffer struct
type AUXBuffer struct {
	RPCHeader RPCHeader
	Buff      []AuxInfo
}

// AUXHeader struct
type AUXHeader struct {
	Size    uint16 //
	Version uint8
	Type    uint8
}

// AUXPerfAccountInfo used for aux info
type AUXPerfAccountInfo struct {
	Header   AUXHeader
	ClientID uint16
	Reserved uint16
	Account  []byte
}

// AUXTypePerfSessionInfo used for aux info
type AUXTypePerfSessionInfo struct {
	Header       AUXHeader
	SessionID    uint16
	Reserved     uint16
	SessionGUID  []byte
	ConnectionID uint32
}

// AUXTPerfMDBSuccess used for aux info
type AUXTPerfMDBSuccess struct {
	Header                AUXHeader
	ClientID              uint16
	ServerID              uint16
	SessionID             uint16
	RequestID             uint16
	TimeSinceRequest      uint32
	TimeToCompleteRequest uint32
}

// AUXTypePerfRequestID used for aux info
type AUXTypePerfRequestID struct {
	Header    AUXHeader
	SessionID uint16
	RequestID uint16
}

// AUXTypePerfProcessInfo used for aux info
type AUXTypePerfProcessInfo struct {
	Header            AUXHeader
	ProcessID         uint16
	Reserved          uint16
	ProcessGUID       []byte
	ProcessNameOffset uint16
	Reserved2         uint16
	ProcessName       []byte
}

// AUXPerfClientInfo used for aux info
type AUXPerfClientInfo struct {
	Header             AUXHeader
	AdapterSpeed       uint32
	ClientID           uint16
	MachineNameOffset  uint16
	UserNameOffset     uint16
	ClientIPSize       uint16
	ClientIPOffset     uint16
	ClientIPMaskSize   uint16
	ClientIPMaskOffset uint16
	AdapterNameOffset  uint16
	MacAddressSize     uint16
	MacAddressOffset   uint16
	ClientMode         uint16
	Reserved           uint16
	MachineName        []byte
	UserName           []byte
	ClientIP           []byte
	ClientIPMask       []byte
	AdapterName        []byte
	MacAddress         []byte
}

// AUXClientConnectionInfo used for aux info
type AUXClientConnectionInfo struct {
	Header                      AUXHeader
	ConnectionGUID              []byte
	OffsetConnectionContextInfo uint16
	Reserved                    uint16
	ConnectionAttempts          uint32
	ConnectionFlags             uint32
	ConnectionContextInfo       []byte
}

// AUXPerfGCSuccess used for aux info
type AUXPerfGCSuccess struct {
	Header                AUXHeader
	ClientID              uint16
	ServerID              uint16
	Reserved              uint16
	TimeSinceRequest      uint32
	TimeToCompleteRequest uint32
	RequestOperation      uint8
	Reserved2             []byte
}

// RTSPing an RTSPing message keeping the channel alive
type RTSPing struct {
	Header RTSHeader
	Sec    RTSSec
}

// Cookie used the connection/channel cookie
type Cookie struct {
	CommandType uint32 //always going to be 03
	Cookie      []byte //16 byte
}

// AssociationGroupID used to hold the group id
type AssociationGroupID struct {
	CommandType        uint32
	AssociationGroupID []byte //16 byte
}

// ChannelLifetime holds lifetime of channel
type ChannelLifetime struct {
	CommandType     uint32 //always 04
	ChannelLifetime uint32 //range of 128kb to 2 Gb
}

// ClientKeepalive specifies how long the channel is kept open
type ClientKeepalive struct {
	CommandType     uint32 //always 05
	ClientKeepalive uint32 //range of 128kb to 2 Gb
}

// AuxInfo interface to make Aux buffers generic
type AuxInfo interface {
	Marshal() []byte
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

// Bind function Creates a Bind Packet
func Bind() BindPDU {
	bind := BindPDU{}
	header := RTSHeader{Version: 0x05, VersionMinor: 0, Type: DCERPC_PKT_BIND, PFCFlags: 0x13, AuthLen: 0, CallID: 1}
	header.PackedDrep = 16

	bind.Header = header

	bind.MaxFrag = 0x0ff8
	bind.MaxRecvFrag = 0x0ff8
	bind.AssociationGroupID = 0x00
	bind.CtxNum = 0x02

	ctx := CTX{}
	ctx.ContextID = 0
	ctx.TransItems = 1
	ctx.AbstractSyntax = []byte{0x00, 0xdb, 0xf1, 0xa4, 0x47, 0xca, 0x67, 0x10, 0xb3, 0x1f, 0x00, 0xdd, 0x01, 0x06, 0x62, 0xda, 0x00, 0x00, 0x51, 0x00} //CookieGen()
	ctx.TransferSyntax = []byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00}

	ctx2 := CTX{}
	ctx2.ContextID = 1
	ctx2.TransItems = 1
	ctx2.AbstractSyntax = ctx.AbstractSyntax
	ctx2.TransferSyntax = append(CookieGen(), []byte{0x01, 0x00, 0x00, 0x00}...) //[]byte{0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}

	bind.CtxItems = append(ctx.Marshal(), ctx2.Marshal()...)
	//unknown PDU data here
	bind.Header.FragLen = uint16(len(bind.Marshal()))

	return bind
}

func SecureBind(authLevel, authType uint8, session *ntlm.ClientSession) BindPDU {
	bind := BindPDU{}
	header := RTSHeader{Version: 0x05, VersionMinor: 0, Type: DCERPC_PKT_BIND, PFCFlags: 0x17, AuthLen: 0, CallID: 1}
	header.PackedDrep = 16

	bind.Header = header

	bind.MaxFrag = 0x0ff8
	bind.MaxRecvFrag = 0x0ff8
	bind.AssociationGroupID = 0
	bind.CtxNum = 0x01

	ctx := CTX{}
	ctx.ContextID = 1
	ctx.TransItems = 1
	ctx.AbstractSyntax = []byte{0x00, 0xdb, 0xf1, 0xa4, 0x47, 0xca, 0x67, 0x10, 0xb3, 0x1f, 0x00, 0xdd, 0x01, 0x06, 0x62, 0xda, 0x00, 0x00, 0x51, 0x00} //CookieGen()
	//ctx.AbstractSyntax = []byte{0x18, 0x5a, 0xcc, 0xf5, 0x64, 0x42, 0x1a, 0x10, 0x8c, 0x59, 0x08, 0x00, 0x2b, 0x2f, 0x84, 0x26, 0x38, 0x00, 0x00, 0x00} //CookieGen()
	ctx.TransferSyntax = []byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00}

	bind.CtxItems = ctx.Marshal()

	/*
		ctx = CTX{}
		ctx.ContextID = 1
		ctx.TransItems = 1
		//ctx.AbstractSyntax = []byte{0x00, 0xdb, 0xf1, 0xa4, 0x47, 0xca, 0x67, 0x10, 0xb3, 0x1f, 0x00, 0xdd, 0x01, 0x06, 0x62, 0xda, 0x00, 0x00, 0x51, 0x00} //CookieGen()
		ctx.AbstractSyntax = []byte{0x18, 0x5a, 0xcc, 0xf5, 0x64, 0x42, 0x1a, 0x10, 0x8c, 0x59, 0x08, 0x00, 0x2b, 0x2f, 0x84, 0x26, 0x38, 0x00, 0x00, 0x00} //CookieGen()
		ctx.TransferSyntax = []byte{0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	*/
	//bind.CtxItems = append(bind.CtxItems, ctx.Marshal()...)
	//unknown PDU data here
	bind.Header.FragLen = uint16(len(bind.Marshal()))

	//setup our auth here
	//for now just WINNT auth, should add GSSP_NEGOTIATE / NETLOGON?
	if authType == RPC_C_AUTHN_WINNT {
		secTrailer := RTSSec{}
		secTrailer.AuthType = authType
		secTrailer.AuthLevel = authLevel
		secTrailer.AuthCTX = 0

		b, _ := rpcntlmsession.GenerateNegotiateMessage()
		bind.AuthData = b.Bytes()
		bind.Header.AuthLen = uint16(len(bind.AuthData))

		bind.SecTrailer = secTrailer.Marshal()
		bind.Header.FragLen = uint16(len(bind.Marshal()))
	}

	return bind
}

func Auth3(authLevel, authType uint8, authData []byte) Auth3Request {
	auth := Auth3Request{}
	header := RTSHeader{Version: 0x05, VersionMinor: 0, Type: DCERPC_PKT_AUTH_3, PFCFlags: 0x17, AuthLen: 0, CallID: 1}
	header.PackedDrep = 16
	header.PFCFlags = header.PFCFlags | 0x04
	auth.Header = header

	auth.MaxFrag = 0x0ff8
	auth.MaxRecvFrag = 0x0ff8

	if authType == RPC_C_AUTHN_WINNT {
		secTrailer := RTSSec{}
		secTrailer.AuthType = authType
		secTrailer.AuthLevel = authLevel
		secTrailer.AuthCTX = 0

		//pad if necessary
		pad := 0 //(4 - (len(authData) % 4)) % 4
		authData = append(authData, bytes.Repeat([]byte{0xBB}, pad)...)
		auth.AuthData = authData

		secTrailer.AuthPadLen = uint8(pad)
		auth.Header.AuthLen = uint16(len(auth.AuthData))

		auth.SecTrailer = secTrailer.Marshal()
		auth.Header.FragLen = uint16(len(auth.Marshal()))
	}
	return auth
}

// ConnA1 sent from the client to create the input channel
func ConnA1(channelCookie []byte) CONNA1 {
	conna1 := CONNA1{}
	header := RTSHeader{Version: 0x05, VersionMinor: 0, Type: DCERPC_PKT_RTS, PFCFlags: 0x03, AuthLen: 0, CallID: 0}
	header.PackedDrep = 16
	conna1.Flags = RTS_FLAG_NONE
	conna1.NumberOfCommands = 4
	conna1.Header = header
	conna1.Version = []byte{0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	conna1.VirtualConnectCookie = Cookie{3, channelCookie}
	conna1.OutChannelCookie = Cookie{3, CookieGen()}
	conna1.ReceiveWindowSize = []byte{00, 00, 00, 00, 00, 00, 00, 01, 00}
	conna1.Header.FragLen = uint16(len(conna1.Marshal()) - 1)
	return conna1
}

// ConnB1 sent from the client to create the output channel
func ConnB1() CONNB1 {
	connb1 := CONNB1{}
	header := RTSHeader{Version: 0x05, VersionMinor: 0, Type: DCERPC_PKT_RTS, PFCFlags: 0x03, AuthLen: 0, CallID: 0}
	header.PackedDrep = 16
	connb1.Flags = RTS_FLAG_NONE
	connb1.NumberOfCommands = 6
	connb1.Header = header
	connb1.Version = []byte{0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	connb1.VirtualConnectCookie = Cookie{3, CookieGen()}
	connb1.InChannelCookie = Cookie{3, CookieGen()}
	connb1.ChannelLifetime = ChannelLifetime{4, 1073741824}
	connb1.ClientKeepAlive = ClientKeepalive{5, 300000}
	connb1.AssociatonGroupID = AssociationGroupID{12, CookieGen()}
	connb1.Header.FragLen = uint16(len(connb1.Marshal()))
	return connb1
}

// Ping function creates a Ping Packet
func Ping() RTSPing {
	ping := RTSPing{}
	ping.Header = RTSHeader{Version: 0x05, VersionMinor: 0, Type: DCERPC_PKT_RTS, PFCFlags: 0x03, AuthLen: 0, CallID: 0}
	ping.Header.FragLen = 20
	//ping.Sec = RTSSec{0x00000010}
	return ping
}

// Unmarshal RPCResponse
func (response *RPCResponse) Unmarshal(raw []byte) (int, error) {
	pos := 0
	response.Header = RTSHeader{}
	response.Header.Version, pos = utils.ReadByte(pos, raw)
	response.Header.VersionMinor, pos = utils.ReadByte(pos, raw)
	response.Header.Type, pos = utils.ReadByte(pos, raw)
	response.Header.PFCFlags, pos = utils.ReadByte(pos, raw)
	response.Header.PackedDrep, pos = utils.ReadUint32(pos, raw)
	response.Header.FragLen, pos = utils.ReadUint16(pos, raw)
	response.Header.AuthLen, pos = utils.ReadUint16(pos, raw)
	response.Header.CallID, pos = utils.ReadUint32(pos, raw)

	if response.Header.AuthLen == 0 {
		if len(raw) > int(response.Header.FragLen)-pos {
			response.PDU, pos = utils.ReadBytes(pos, int(response.Header.FragLen)-pos, raw)
		} else {
			response.PDU, pos = utils.ReadBytes(pos, len(raw)-pos, raw)
		}
	} else {
		if len(raw) > int(response.Header.FragLen-response.Header.AuthLen-24) {
			response.PDU, pos = utils.ReadBytes(pos, int(response.Header.FragLen-response.Header.AuthLen-24), raw)
			if len(raw) < pos+int(response.Header.AuthLen) {
				return pos, nil
			}
			response.SecTrailer, pos = utils.ReadBytes(pos, int(response.Header.AuthLen), raw)
		}
	}
	return pos, nil
}

// Unmarshal the SecTrailer
func (sec *RTSSec) Unmarshal(raw []byte, ln int) (int, error) {
	pos := 0
	sec.AuthType, pos = utils.ReadByte(pos, raw)
	sec.AuthLevel, pos = utils.ReadByte(pos, raw)
	sec.AuthPadLen, pos = utils.ReadByte(pos, raw)
	sec.AuthRsvrd, pos = utils.ReadByte(pos, raw)
	sec.AuthCTX, pos = utils.ReadUint32(pos, raw)
	return pos, nil
}

// Marshal turn RTSPing into Bytes
func (rtsPing RTSPing) Marshal() []byte {
	return utils.BodyToBytes(rtsPing)
}

// Marshal turn Bind into Bytes
func (rtsBind BindPDU) Marshal() []byte {
	return utils.BodyToBytes(rtsBind)
}

// Marshal turn PDUData into Bytes
func (pdu PDUData) Marshal() []byte {
	return utils.BodyToBytes(pdu)
}

// Marshal turn Auth3Request into Bytes
func (authBind Auth3Request) Marshal() []byte {
	return utils.BodyToBytes(authBind)
}

// Marshal turn RTSRequest into Bytes
func (rtsRequest RTSRequest) Marshal() []byte {
	return utils.BodyToBytes(rtsRequest)
}

// Marshal ConnectExRequest into bytes
func (rtsRequest ConnectExRequest) Marshal() []byte {
	return utils.BodyToBytes(rtsRequest)
}

// Marshal connA1
func (connA1Request CONNA1) Marshal() []byte {
	return utils.BodyToBytes(connA1Request)
}

// Marshal connB1
func (connB1Request CONNB1) Marshal() []byte {
	return utils.BodyToBytes(connB1Request)
}

// Marshal CTX
func (ctx CTX) Marshal() []byte {
	return utils.BodyToBytes(ctx)
}

// Marshal RTSSec
func (sec RTSSec) Marshal() []byte {
	return utils.BodyToBytes(sec)
}

// Marshal AuxBuffer
func (auxbuf AUXBuffer) Marshal() []byte {
	return utils.BodyToBytes(auxbuf)
}

// Marshal AUXPerfClientInfo
func (auxbuf AUXPerfClientInfo) Marshal() []byte {
	return utils.BodyToBytes(auxbuf)
}

// Marshal AUXPerfAccountInfo
func (auxbuf AUXPerfAccountInfo) Marshal() []byte {
	return utils.BodyToBytes(auxbuf)
}

// Marshal AUXTypePerfSessionInfo
func (auxbuf AUXTypePerfSessionInfo) Marshal() []byte {
	return utils.BodyToBytes(auxbuf)
}

// Marshal AUXTypePerfProcessInfo
func (auxbuf AUXTypePerfProcessInfo) Marshal() []byte {
	return utils.BodyToBytes(auxbuf)
}

// Marshal AUXTypePerfRequestID
func (auxbuf AUXTypePerfRequestID) Marshal() []byte {
	return utils.BodyToBytes(auxbuf)
}

// Marshal AUXTPerfMDBSuccess
func (auxbuf AUXTPerfMDBSuccess) Marshal() []byte {
	return utils.BodyToBytes(auxbuf)
}

// Marshal AUXClientConnectionInfo
func (auxbuf AUXClientConnectionInfo) Marshal() []byte {
	return utils.BodyToBytes(auxbuf)
}

// Marshal AUXPerfGCSuccess
func (auxbuf AUXPerfGCSuccess) Marshal() []byte {
	return utils.BodyToBytes(auxbuf)
}
