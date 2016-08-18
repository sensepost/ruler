package mapi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
)

var uFlagsUser = []byte{0x00, 0x00, 0x00, 0x00}
var uFlagsAdmin = []byte{0x00, 0x00, 0x00, 0x01}
var uFlagsNotSpecified = []byte{0x00, 0x00, 0x80, 0x00}

var ropFlagsCompression = []byte{0x01, 0x00} //LittleEndian 0x000001
var ropFlagsXorMagic = []byte{0x02, 0x00}    //LittleEndian 0x000002
var ropFlagsChain = []byte{0x04, 0x00}       //LittleEndian 0x000004

//ruletags
var PidTagRuleId = []byte{0x14, 0x00, 0x74, 0x66}
var PidTagRuleName = []byte{0x1F, 0x00, 0x82, 0x66}
var PidTagRuleSequence = []byte{0x03, 0x00, 0x76, 0x66}
var PidTagRuleState = []byte{0x03, 0x00, 0x77, 0x66}
var PidTagRuleCondition = []byte{0xFD, 0x00, 0x79, 0x66}
var PidTagRuleActions = []byte{0xFE, 0x00, 0x80, 0x66}
var PidTagRuleProvider = []byte{0x1F, 0x00, 0x81, 0x66}
var PidTagRuleProviderData = []byte{0x02, 0x01, 0x84, 0x66}
var PidTagRuleLevel = []byte{0x03, 0x00, 0x83, 0x66}

//ConnectRequest struct
type ConnectRequest struct {
	UserDN            []byte
	Flags             []byte
	DefaultCodePage   uint32
	LcidSort          uint32
	LcidString        uint32
	AuxilliaryBufSize uint32
	AuxilliaryBuf     []byte
}

//ExecuteRequest struct
type ExecuteRequest struct {
	Flags             []byte //lets stick to ropFlagsNoXorMagic
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
	Version    []byte //always 0x0000
	Flags      []byte //0x0001 Compressed, 0x0002 XorMagic, 0x0004 Last
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
	RopID             byte //0xfe
	LogonID           byte //logonID to use
	OutputHandleIndex byte
	LogonFlags        byte
	OpenFlags         []byte
	StoreState        []byte //0x00000000
	EssdnSize         uint16
	Essdn             []byte
}

//RopLogonResponse struct
type RopLogonResponse struct {
	RopID             byte //0xfe
	OutputHandleIndex byte
	ReturnValue       uint32
	LogonFlags        byte
	FolderIds         []byte //0x00000000
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
	RopID             byte //0x3f
	LogonID           byte
	InputHandleIndex  byte
	OutputHandleIndex byte
	TableFlags        byte
}

//RopModifyRulesRequestBuffer struct
type RopModifyRulesRequestBuffer struct {
	RopID            byte //0x02
	LogonID          byte
	InputHandleIndex byte
	ModifyRulesFlag  byte
	RulesCount       uint16
	RulesData        []byte
}

//RopGetContentsTableResponse struct
type RopGetContentsTableResponse struct {
	RopID        byte //0x05
	OutputHandle byte
	ReturnValue  uint32
	RowCount     uint32
	Rows         []byte
}

//ModRuleData struct
type ModRuleData struct {
	RopID            byte //0x41
	LoginID          byte
	InputHandleIndex byte
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
	Type        byte   //0x03 RES_CONTENT
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
	PropertyTag   []byte //PropertyTag
	PropertyValue []byte
}

//PropertyTag struct
type PropertyTag struct {
	PropertyType uint16
	PropertyID   uint16
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
	auxBuf.RPCHeader.Version, pos = readBytes(pos, 2, buff)
	auxBuf.RPCHeader.Flags, pos = readBytes(pos, 2, buff)
	auxBuf.RPCHeader.Size, pos = readUint16(pos, buff)
	auxBuf.RPCHeader.SizeActual, _ = readUint16(pos, buff)
	auxBuf.Header = AUXHeader{}
	auxBuf.Header.Size = uint16(1)
	return auxBuf
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

//CalcSizes func to calculate the different size fields in the ROP buffer
func (execRequest *ExecuteRequest) CalcSizes() error {
	execRequest.RopBuffer.ROP.RopSize = uint16(len(execRequest.RopBuffer.ROP.RopsList) + 2)
	execRequest.RopBuffer.Header.Size = uint16(len(BodyToBytes(execRequest.RopBuffer.ROP)))
	execRequest.RopBuffer.Header.SizeActual = execRequest.RopBuffer.Header.Size
	execRequest.RopBufferSize = uint32(len(BodyToBytes(execRequest.RopBuffer)))
	return nil
}

func (execRequest *ExecuteRequest) Init() {
	execRequest.Flags = []byte{0x02, 0x00, 0x00, 0x00}

	execRequest.RopBuffer.Header.Version = []byte{0x00, 0x00}
	execRequest.RopBuffer.Header.Flags = []byte{0x04, 0x00} //ropFlagsChain
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
		fmt.Println("Bad GetRUles")
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
