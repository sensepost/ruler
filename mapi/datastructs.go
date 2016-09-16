package mapi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
)

const (
	uFlagsUser         = 0x00000000
	uFlagsAdmin        = 0x00000001
	uFlagsNotSpecified = 0x00008000
)

const (
	ropFlagsCompression = 0x0001 //[]byte{0x01, 0x00} //LittleEndian 0x0001
	ropFlagsXorMagic    = 0x0002 //[]byte{0x02, 0x00}    //LittleEndian 0x0002
	ropFlagsChain       = 0x0004 //[]byte{0x04, 0x00}       //LittleEndian 0x0004
)

//PidTagRuleID the TaggedPropertyValue for rule id
var PidTagRuleID = PropertyTag{PtypInteger64, 0x6674}

//PidTagRuleName the TaggedPropertyValue for rule id
var PidTagRuleName = PropertyTag{PtypString, 0x6682}

//PidTagRuleSequence the TaggedPropertyValue for rule id
var PidTagRuleSequence = PropertyTag{PtypInteger32, 0x6676}

//PidTagRuleState the TaggedPropertyValue for rule id
var PidTagRuleState = PropertyTag{PtypInteger32, 0x6677}

//PidTagRuleCondition the TaggedPropertyValue for rule id
var PidTagRuleCondition = PropertyTag{PtypRestriction, 0x6679}

//PidTagRuleActions the TaggedPropertyValue for rule id
var PidTagRuleActions = PropertyTag{PtypRuleAction, 0x6680}

//PidTagRuleProvider the TaggedPropertyValue for rule id
var PidTagRuleProvider = PropertyTag{PtypString, 0x6681}

//PidTagRuleProviderData the TaggedPropertyValue for rule id
var PidTagRuleProviderData = PropertyTag{PtypBinary, 0x6684}

//PidTagRuleLevel the TaggedPropertyValue for rule level
var PidTagRuleLevel = PropertyTag{PtypInteger32, 0x6683}

//OpenFlags
const (
	UseAdminPrivilege       = 0x00000001
	Public                  = 0x00000002
	HomeLogon               = 0x00000004
	TakeOwnership           = 0x00000008
	AlternateServer         = 0x00000100
	IgnoreHomeMDB           = 0x00000200
	NoMail                  = 0x00000400
	UserPerMdbReplidMapping = 0x01000000
	SupportProgress         = 0x20000000
)

//Property Data types
const (
	PtypInteger16      = 0x0002
	PtypInteger32      = 0x0003
	PtypInteger64      = 0x0014
	PtypFloating32     = 0x0004
	PtypFloating64     = 0x0005
	PtypBoolean        = 0x000B
	PtypString         = 0x001F
	PtypString8        = 0x001E
	PtypGUID           = 0x0048
	PtypRuleAction     = 0x00FE
	PtypRestriction    = 0x00FD
	PtypBinary         = 0x0102
	PtypMultipleBinary = 0x1102
)

//Folder id/locations -- https://msdn.microsoft.com/en-us/library/office/cc815825.aspx
const (
	OUTBOX   = 0 //Contains outgoing IPM messages.
	DELETED  = 1 //Contains IPM messages that are marked for deletion.
	SENT     = 2 //Contains IPM messages that have been sent.
	IPM      = 3 //IPM root folder Contains folders for managing IPM messages.
	INBOX    = 4 //Receive folder Contains incoming messages for a particular message class.
	SEARCH   = 5 //Search-results root folder Contains folders for managing search results.
	COMMON   = 6 //Common-views root folder Contains folders for managing views for the message store.
	PERSONAL = 7 //Personal-views root folder
)

//ConnectRequest struct
type ConnectRequest struct {
	UserDN            []byte
	Flags             uint32
	DefaultCodePage   uint32
	LcidSort          uint32
	LcidString        uint32
	AuxilliaryBufSize uint32
	AuxilliaryBuf     []byte
}

//DisconnectRequest structure
type DisconnectRequest struct {
	AuxilliaryBufSize uint32
	AuxilliaryBuf     []byte
}

//ExecuteRequest struct
type ExecuteRequest struct {
	Flags             uint32 //[]byte //lets stick to ropFlagsNoXorMagic
	RopBufferSize     uint32
	RopBuffer         ROPBuffer
	MaxRopOut         uint32
	AuxilliaryBufSize uint32
	AuxilliaryBuf     []byte
}

//ExecuteResponse struct
type ExecuteResponse struct {
	StatusCode        uint32 //if 0x00000 --> failure and we only have AuzilliaryBufferSize and AuxilliaryBuffer
	ErrorCode         uint32
	Flags             []byte //0x00000000
	RopBufferSize     uint32
	RopBuffer         []byte //struct{}
	AuxilliaryBufSize uint32
	AuxilliaryBuf     []byte
}

//ConnectResponse strcut
type ConnectResponse struct {
	StatusCode           uint32 //if 0x00000 --> failure and we only have AuzilliaryBufferSize and AuxilliaryBuffer
	ErrorCode            uint32
	PollsMax             uint32
	RetryCount           uint32
	RetryDelay           uint32
	DNPrefix             []byte
	DisplayName          []byte
	AuxilliaryBufferSize uint32
	AuxilliaryBuffer     []byte
}

//RgbAuxIn struct
type RgbAuxIn struct {
	RPCHeader RPCHeader
}

//RPCHeader struct
type RPCHeader struct {
	Version    uint16 //always 0x0000
	Flags      uint16 //0x0001 Compressed, 0x0002 XorMagic, 0x0004 Last
	Size       uint16
	SizeActual uint16 //Compressed size (if 0x0001 set)
}

//ROPBuffer struct
type ROPBuffer struct {
	Header RPCHeader
	ROP    ROP
}

//ROP request
type ROP struct {
	RopSize                 uint16
	RopsList                []byte
	ServerObjectHandleTable []byte
}

//RopLogonRequest struct
type RopLogonRequest struct {
	RopID             uint8 //0xfe
	LogonID           uint8 //logonID to use
	OutputHandleIndex uint8
	LogonFlags        byte
	OpenFlags         uint32 //[]byte
	StoreState        uint32 //0x00000000
	EssdnSize         uint16
	Essdn             []byte
}

//RopDisconnectRequest struct
type RopDisconnectRequest struct {
	RopID            uint8 //0x01
	LogonID          uint8 //logonID to use
	InputHandleIndex uint8
}

//RopLogonResponse struct
type RopLogonResponse struct {
	RopID             uint8
	OutputHandleIndex uint8
	ReturnValue       uint32
	LogonFlags        byte
	FolderIds         []byte
	ResponseFlags     byte
	MailboxGUID       []byte
	RepID             []byte
	ReplGUID          []byte
	LogonTime         []byte
	GwartTime         []byte
	StoreState        []byte
}

//RopGetRulesRequestData struct
type RopGetRulesRequestData struct {
	RopID             uint8 //0x3f
	LogonID           uint8
	InputHandleIndex  uint8
	OutputHandleIndex uint8
	TableFlags        byte
}

//RopModifyRulesRequestBuffer struct
type RopModifyRulesRequestBuffer struct {
	RopID            uint8 //0x02
	LogonID          uint8
	InputHandleIndex uint8
	ModifyRulesFlag  byte
	RulesCount       uint16
	RulesData        []byte
}

//RopGetContentsTableResponse struct
type RopGetContentsTableResponse struct {
	RopID        uint8 //0x05
	OutputHandle uint8
	ReturnValue  uint32
	RowCount     uint32
	Rows         []byte
}

//RopGetPropertiesSpecific struct to get propertiesfor a folder
type RopGetPropertiesSpecific struct {
	RopID             uint8 //0x07
	LogonID           uint8
	InputHandle       uint8
	PropertySizeLimit uint16
	WantUnicode       []byte //apparently bool
	PropertyTagCount  uint16
	PropertyTags      []byte
}

//RopOpenFolder struct used to open a folder
type RopOpenFolder struct {
	RopID         uint8 //0x02
	LogonID       uint8
	InputHandle   uint8
	OutputHandle  uint8
	FolderID      []byte
	OpenModeFlags uint8
}

//RopOpenFolderResponse struct used to open a folder
type RopOpenFolderResponse struct {
	RopID            uint8
	OutputHandle     uint8
	ReturnValue      uint32
	HasRules         byte   //bool
	IsGhosted        byte   //bool
	ServerCount      uint16 //only if IsGhosted == true
	CheapServerCount uint16 //only if IsGhosted == true
	Servers          []byte //only if IsGhosted == true
}

//RopCreateMessage struct used to open handle to new email message
type RopCreateMessage struct {
	RopID          uint8
	LogonID        uint8
	InputHandle    uint8
	OutputHandle   uint8
	CodePageID     uint16
	FolderID       []byte
	AssociatedFlag byte //bool
}

//RopOpenMessageRequest struct used to open handle to  message
type RopOpenMessageRequest struct {
	RopID         uint8 //0x03
	LogonID       uint8
	InputHandle   uint8
	OutputHandle  uint8
	CodePageID    uint16
	FolderID      []byte
	OpenModeFlags byte
	MessageID     []byte
}

//RopOpenStreamRequest struct used to open a stream
type RopOpenStreamRequest struct {
	RopID         uint8 //0x2B
	LogonID       uint8
	InputHandle   uint8
	OutputHandle  uint8
	PropertyTag   []byte
	OpenModeFlags byte
}

//RopReadStreamRequest struct used to open a stream
type RopReadStreamRequest struct {
	RopID            uint8 //0x2C
	LogonID          uint8
	InputHandle      uint8
	ByteCount        uint16
	MaximumByteCount uint32
}

//RopSetColumnsRequest struct used to select the columns to use
type RopSetColumnsRequest struct {
	RopID            uint8 //0x12
	LogonID          uint8
	InputHandle      uint8
	SetColumnFlags   uint8
	PropertyTagCount uint16
	PropertyTags     []PropertyTag
}

//RopQueryRowsRequest struct used to select the columns to use
type RopQueryRowsRequest struct {
	RopID          uint8 //0x15
	LogonID        uint8
	InputHandle    uint8
	QueryRowsFlags uint8
	ForwardRead    byte
	RowCount       uint16
}

//RopReleaseRequest struct used to release all resources associated with a server object
type RopReleaseRequest struct {
	RopID       uint8 //0x01
	LogonID     uint8
	InputHandle uint8
}

//RopCreateMessageResponse struct used to open handle to new email message
type RopCreateMessageResponse struct {
	RopID        uint8
	OutputHandle uint8
	ReturnValue  uint32
	HasMessageID byte   //bool
	MessageID    []byte //bool
}

//RopModifyRulesRequest struct
type RopModifyRulesRequest struct {
	RopID            uint8 //0x41
	LoginID          uint8
	InputHandleIndex uint8
	ModifyRulesFlag  byte
	RulesCount       uint16
	RuleData         RuleData
}

//RuleData struct
type RuleData struct {
	RuleDataFlags      byte
	PropertyValueCount uint16
	PropertyValues     []TaggedPropertyValue //[]byte
}

//RuleActionBlock struct
type RuleActionBlock struct {
	ActionLength uint16
	ActionType   byte   //0x05 -- DEFER
	ActionFlavor []byte //0x00000000
	ActionFlags  []byte //0x00000000
	ActionData   []byte
}

//Rule struct
type Rule struct {
	HasFlag      byte
	RuleID       []byte
	RuleProvider []byte
	RuleName     []byte
}

//RuleCondition struct
type RuleCondition struct {
	Type        uint8  //0x03 RES_CONTENT
	FuzzyLevel  []byte //0x00010001 //FL_SUBSTRING | IgnoreCase
	PropertyTag []byte //where to look -- subject: 0x0037001F
	Value       []byte //
}

//RuleAction struct
type RuleAction struct {
	Actions      uint16
	ActionLen    uint16
	ActionType   byte   //DEFER == 0x05
	ActionFlavor uint32 //0x00000000
	ActionFlags  uint32 //0x00000000
	ActionData   ActionData
}

//ActionData struct
type ActionData struct {
	ActionElem []byte
	//NameLen    uint8
	ActionName []byte
	Element    []byte
	//TriggerLen  uint8
	Triggger []byte
	Elem     []byte
	//EndpointLen uint8
	EndPoint []byte
	Footer   []byte
}

//TaggedPropertyValue struct
type TaggedPropertyValue struct {
	PropertyTag   PropertyTag
	PropertyValue []byte
}

//PropertyTag struct
type PropertyTag struct {
	PropertyType uint16
	PropertyID   uint16 //[]byte //uint16
}

//AUXBuffer struct
type AUXBuffer struct {
	RPCHeader RPCHeader
	Header    AUXHeader
}

//AUXHeader struct
type AUXHeader struct {
	Size    uint16 //
	Version []byte //0x01, 0x02
	Type    []byte //AUX_TYPE_PERF_CLIENTINFO 0x02
}

//RopResponse interface for common methods on RopResponses
type RopResponse interface {
	Unmarshal([]byte) error
}

//RopRequest interface for common methods on RopRequests
type RopRequest interface {
	Marshal(DataStruct interface{}) []byte
}

//RopBuffer interface for common methods on RopBuffer Data
type RopBuffer interface {
	Unmarshal([]byte) error
}

//UniString func
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

func decodeUint32(num []byte) uint32 {
	var number uint32
	bf := bytes.NewReader(num)
	binary.Read(bf, binary.LittleEndian, &number)
	return number
}
func decodeUint16(num []byte) uint16 {
	var number uint16
	bf := bytes.NewReader(num)
	binary.Read(bf, binary.LittleEndian, &number)
	return number
}
func encodeNum(v interface{}) []byte {
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
				if v.Index(i).Kind() == reflect.Struct || v.Index(i).Kind() == reflect.Slice {
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
				if v.Field(i).Kind() == reflect.Struct || v.Field(i).Kind() == reflect.Slice {
					value = BodyToBytes(v.Field(i).Interface())
				} else {
					value = v.Field(i).Bytes()
				}
				dumped = append(dumped, value...)
			}
		}
	}
	return dumped
}

func readUint32(pos int, buff []byte) (uint32, int) {
	return decodeUint32(buff[pos : pos+4]), pos + 4
}

func readUint16(pos int, buff []byte) (uint16, int) {
	return decodeUint16(buff[pos : pos+2]), pos + 2
}

func readBytes(pos, count int, buff []byte) ([]byte, int) {
	return buff[pos : pos+count], pos + count
}

func readByte(pos int, buff []byte) (byte, int) {
	return buff[pos : pos+1][0], pos + 1
}

func readUnicodeString(pos int, buff []byte) ([]byte, int) {
	//stupid hack as using bufio and ReadString(byte) would terminate too early
	//would terminate on 0x00 instead of 0x0000
	index := bytes.Index(buff[pos:], []byte{0x00, 0x00})
	str := buff[pos : pos+index]
	return []byte(str), pos + index + 2
}
func readASCIIString(pos int, buff []byte) ([]byte, int) {
	bf := bytes.NewBuffer(buff[pos:])
	str, _ := bf.ReadString(0x00)
	return []byte(str), pos + len(str)
}

//DecodeAuxBuffer func
func DecodeAuxBuffer(buff []byte) AUXBuffer {
	pos := 0
	auxBuf := AUXBuffer{}
	auxBuf.RPCHeader = RPCHeader{}
	auxBuf.RPCHeader.Version, pos = readUint16(pos, buff)
	auxBuf.RPCHeader.Flags, pos = readUint16(pos, buff)
	auxBuf.RPCHeader.Size, pos = readUint16(pos, buff)
	auxBuf.RPCHeader.SizeActual, _ = readUint16(pos, buff)
	auxBuf.Header = AUXHeader{}
	auxBuf.Header.Size = uint16(1)
	return auxBuf
}

//Marshal turn ExecuteRequest into Bytes
func (execRequest ExecuteRequest) Marshal() []byte {
	execRequest.CalcSizes()
	return BodyToBytes(execRequest)
}

//Marshal turn ConnectRequest into Bytes
func (connRequest ConnectRequest) Marshal() []byte {
	return BodyToBytes(connRequest)
}

//Marshal turn DisconnectRequest into Bytes
func (disconnectRequest DisconnectRequest) Marshal() []byte {
	return BodyToBytes(disconnectRequest)
}

//Marshal turn RopLogonRequest into Bytes
func (logonRequest RopLogonRequest) Marshal() []byte {
	return BodyToBytes(logonRequest)
}

//Marshal turn the RopQueryRowsRequest into bytes
func (queryRows RopQueryRowsRequest) Marshal() []byte {
	return BodyToBytes(queryRows)
}

//Marshal to turn the RopSetColumnsRequest into bytes
func (setColumns RopSetColumnsRequest) Marshal() []byte {
	return BodyToBytes(setColumns)
}

//Marshal turn RopOpenFolder into Bytes
func (openFolder RopOpenFolder) Marshal() []byte {
	return BodyToBytes(openFolder)
}

//Marshal turn RopGetPropertiesSpecific into Bytes
func (getProps RopGetPropertiesSpecific) Marshal() []byte {
	return BodyToBytes(getProps)
}

//Marshal turn ExecuteRequest into Bytes
func (createMessage RopCreateMessage) Marshal() []byte {
	return BodyToBytes(createMessage)
}

//Marshal turn RopOpenMessageRequest into Bytes
func (openMessage RopOpenMessageRequest) Marshal() []byte {
	return BodyToBytes(openMessage)
}

//Marshal turn RopOpenStreamRequest into Bytes
func (openStream RopOpenStreamRequest) Marshal() []byte {
	return BodyToBytes(openStream)
}

//Marshal turn RopReadStreamRequest into Bytes
func (readStream RopReadStreamRequest) Marshal() []byte {
	return BodyToBytes(readStream)
}

//Marshal turn RuleAction into Bytes
func (ruleAction RuleAction) Marshal() []byte {
	return BodyToBytes(ruleAction)
}

//Marshal turn RopReleaseRequest into Bytes
func (releaseRequest RopReleaseRequest) Marshal() []byte {
	return BodyToBytes(releaseRequest)
}

//Unmarshal function to convert response into ConnectResponse struct
func (connResponse *ConnectResponse) Unmarshal(resp []byte) error {
	pos := 0
	connResponse.StatusCode, pos = readUint32(pos, resp)
	if connResponse.StatusCode != 0 { //error occurred..
		connResponse.AuxilliaryBufferSize, pos = readUint32(pos, resp)
		connResponse.AuxilliaryBuffer = resp[8 : 8+connResponse.AuxilliaryBufferSize]
	} else {
		connResponse.ErrorCode, pos = readUint32(pos, resp)
		connResponse.PollsMax, pos = readUint32(pos, resp)
		connResponse.RetryCount, pos = readUint32(pos, resp)
		connResponse.RetryDelay, pos = readUint32(pos, resp)
		connResponse.DNPrefix, pos = readUnicodeString(pos, resp)
		connResponse.DisplayName, pos = readASCIIString(pos, resp)
		connResponse.AuxilliaryBufferSize, pos = readUint32(pos, resp)
		connResponse.AuxilliaryBuffer = resp[pos:]
	}
	return nil
}

//Unmarshal function to produce RopLogonResponse struct
func (logonResponse *RopLogonResponse) Unmarshal(resp []byte) error {
	pos := 10
	logonResponse.RopID, pos = readByte(pos, resp)
	logonResponse.OutputHandleIndex, pos = readByte(pos, resp)
	logonResponse.ReturnValue, pos = readUint32(pos, resp)
	logonResponse.LogonFlags, pos = readByte(pos, resp)
	logonResponse.FolderIds, pos = readBytes(pos, 104, resp)
	logonResponse.ResponseFlags, pos = readByte(pos, resp)
	logonResponse.MailboxGUID, pos = readBytes(pos, 16, resp)
	logonResponse.RepID, pos = readBytes(pos, 2, resp)
	logonResponse.ReplGUID, pos = readBytes(pos, 16, resp)
	logonResponse.LogonTime, pos = readBytes(pos, 8, resp)
	logonResponse.GwartTime, pos = readBytes(pos, 8, resp)
	logonResponse.StoreState, _ = readBytes(pos, 4, resp)
	return nil
}

//Unmarshal func
func (execResponse *ExecuteResponse) Unmarshal(resp []byte) error {
	pos := 0
	var buf []byte
	execResponse.StatusCode, pos = readUint32(pos, resp)

	if execResponse.StatusCode != 0 { //error occurred..
		execResponse.AuxilliaryBufSize, pos = readUint32(pos, resp)
		execResponse.AuxilliaryBuf = resp[8 : 8+execResponse.AuxilliaryBufSize]
	} else {
		execResponse.ErrorCode, pos = readUint32(pos, resp)
		execResponse.Flags, pos = readBytes(pos, 4, resp)
		execResponse.RopBufferSize, pos = readUint32(pos, resp)
		buf, pos = readBytes(pos, int(execResponse.RopBufferSize), resp)
		execResponse.RopBuffer = buf //decodeLogonRopResponse(buf)
		execResponse.AuxilliaryBufSize, pos = readUint32(pos, resp)
		execResponse.AuxilliaryBuf, _ = readBytes(pos, int(execResponse.AuxilliaryBufSize), resp)
	}
	return nil
}

//Unmarshal func
func (ropContents *RopGetContentsTableResponse) Unmarshal(resp []byte) error {
	pos := 10
	ropContents.RopID, pos = readByte(pos, resp)
	ropContents.OutputHandle, pos = readByte(pos, resp)
	ropContents.ReturnValue, pos = readUint32(pos, resp)
	ropContents.RowCount, pos = readUint32(pos, resp)
	ropContents.Rows = resp[pos:]
	return nil
}

//Unmarshal function to produce RopLogonResponse struct
func (createMessageResponse *RopCreateMessageResponse) Unmarshal(resp []byte) error {
	pos := 10
	createMessageResponse.RopID, pos = readByte(pos, resp)
	createMessageResponse.OutputHandle, pos = readByte(pos, resp)
	createMessageResponse.ReturnValue, pos = readUint32(pos, resp)
	if createMessageResponse.ReturnValue == 0 {
		createMessageResponse.HasMessageID, pos = readByte(pos, resp)
		if createMessageResponse.HasMessageID == 255 {
			createMessageResponse.MessageID, _ = readBytes(pos, 4, resp)
		}
	}
	return nil
}

//CalcSizes func to calculate the different size fields in the ROP buffer
func (execRequest *ExecuteRequest) CalcSizes() error {
	execRequest.RopBuffer.ROP.RopSize = uint16(len(execRequest.RopBuffer.ROP.RopsList) + 2)
	execRequest.RopBuffer.Header.Size = uint16(len(BodyToBytes(execRequest.RopBuffer.ROP)))
	execRequest.RopBuffer.Header.SizeActual = execRequest.RopBuffer.Header.Size
	execRequest.RopBufferSize = uint32(len(BodyToBytes(execRequest.RopBuffer)))
	return nil
}

//Init function to create a base ExecuteRequest object
func (execRequest *ExecuteRequest) Init() {
	execRequest.Flags = 0x00000002
	execRequest.RopBuffer.Header.Version = 0x0000
	execRequest.RopBuffer.Header.Flags = ropFlagsChain //[]byte{0x04, 0x00}
	execRequest.MaxRopOut = 32775
}

//DecodeRulesResponse func
func DecodeRulesResponse(resp []byte) ([]Rule, []byte) {
	pos := 10

	var ret uint32
	var rowcount uint16
	_, pos = readByte(pos, resp)     //RopGetRulesTable should be 0x3f
	_, pos = readByte(pos, resp)     //RopGetRulesTable InputHandleIndex
	ret, pos = readUint32(pos, resp) //check that no error
	if ret != 0 {
		fmt.Println("Bad GetRules")
		return nil, nil
	}
	_, pos = readByte(pos, resp)     //RopSetColumns should be 0x12
	_, pos = readByte(pos, resp)     //RopSetColumns InputHandleIndex
	ret, pos = readUint32(pos, resp) //check that no error
	if ret != 0 {
		fmt.Println("Bad SetColumns")
		return nil, nil
	}
	_, pos = readByte(pos, resp)

	_, pos = readByte(pos, resp)     //(RopQueryRows) should be 0x15
	_, pos = readByte(pos, resp)     //(RopQueryRows) InputHandleIndex
	ret, pos = readUint32(pos, resp) //check that no error
	if ret != 0 {
		fmt.Println("Bad QueryRows")
		return nil, nil
	}
	_, pos = readByte(pos, resp)
	rowcount, pos = readUint16(pos, resp)

	rules := make([]Rule, rowcount)

	for k := 0; k < int(rowcount); k++ {
		rule := Rule{}
		rule.HasFlag, pos = readByte(pos, resp)
		rule.RuleID, pos = readBytes(pos, 8, resp)
		rule.RuleName, pos = readUnicodeString(pos, resp)
		rules[k] = rule
		pos++
	}
	ruleshandle := resp[pos+4:]

	return rules, ruleshandle
}
