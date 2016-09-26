package utils

//Constants for RTS header flags
const (
	RTSFLAGNONE           = 0x0000
	RTSFLAGPING           = 0x0001
	RTSFLAGOTHERCMD       = 0x0002
	RTSFLAGRECYCLECHANNEL = 0x0004
	RTSFLAGINCHANNEL      = 0x0008
	RTSFLAGOUTCHANNEL     = 0x0010
	RTSFLAGEOF            = 0x0020
	RTSFLAGECHO           = 0x0040
)

//RTSHeader structure for unmarshal
type RTSHeader struct {
	RPCVersion       uint8 //05
	RPCVersionMinor  uint8 //00
	PType            byte
	PFCFlags         byte
	PackedDrep       []byte
	FragLen          uint16
	AuthLen          uint16
	CallID           uint32
	Flags            uint16
	NumberOfCommands uint16
}
