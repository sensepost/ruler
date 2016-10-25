package rpchttp

//RTSHeader struct
type RTSHeader struct {
	Version          byte
	VersionMinor     byte
	PTYPE            byte
	PfcFlags         byte
	PackedDREP       uint32 //4 bytes
	FragLength       uint16
	AuthLength       uint16
	CallID           uint32 //4 bytes
	Flags            uint16
	NumberOfCommands uint16
}

//BindPDU struct
type BindPDU struct {
	UserDN            []byte
	Flags             uint32
	DefaultCodePage   uint32
	LcidSort          uint32
	LcidString        uint32
	AuxilliaryBufSize uint32
	AuxilliaryBuf     []byte
}
