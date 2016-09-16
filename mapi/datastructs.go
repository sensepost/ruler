package mapi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
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

//RopGetRulesRequest struct
type RopGetRulesRequest struct {
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

//RopGetContentsTableRequest struct
type RopGetContentsTableRequest struct {
	RopID             uint8 //0x05
	LogonID           uint8
	InputHandleIndex  uint8
	OutputHandleIndex uint8
	TableFlags        uint8
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
	PropertyTags      []PropertyTag //[]byte
}

//RopGetPropertiesSpecificResponse struct to get propertiesfor a folder
type RopGetPropertiesSpecificResponse struct {
	RopID             uint8 //0x07
	InputHandleIndex  uint8
	ReturnValue       uint32
	PropertySizeLimit uint16
	RowData           []PropertyRow
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

//RopRestrictRequest strcut
type RopRestrictRequest struct {
	RopID            uint8 //0x14
	LogonID          uint8
	InputHandle      uint8
	RestrictFlags    uint8
	RestrictDataSize uint16
	RestrictionData  []byte
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

//RopSetColumnsResponse struct used to select the columns to use
type RopSetColumnsResponse struct {
	RopID       uint8 //0x12
	InputHandle uint8
	ReturnValue uint32
	TableStatus uint8
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

//RopQueryRowsResponse struct used to select the columns to use
type RopQueryRowsResponse struct {
	RopID       uint8 //0x15
	InputHandle uint8
	ReturnValue uint32
	Origin      byte
	RowCount    uint16
	RowData     [][]PropertyRow
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

//RopGetRulesTableResponse strcut
type RopGetRulesTableResponse struct {
	RopID        uint8
	OutputHandle uint8
	ReturnValue  uint32
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

//PropertyRow used to hold the data of getRow requests such as RopGetPropertiesSpecific
type PropertyRow struct {
	Flag       uint8 //non-zero indicates error
	ValueArray []byte
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

func decodeUint8(num []byte) uint8 {
	var number uint8
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
func readUint8(pos int, buff []byte) (uint8, int) {
	return decodeUint8(buff[pos : pos+2]), pos + 2
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

//Marshal turn RopGetContentsTableRequest into Bytes
func (getContentsTable RopGetContentsTableRequest) Marshal() []byte {
	return BodyToBytes(getContentsTable)
}

//Marshal turn RopGetRulesRequest into Bytes
func (getRules RopGetRulesRequest) Marshal() []byte {
	return BodyToBytes(getRules)
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

//Unmarshal func
func (queryRows *RopQueryRowsResponse) Unmarshal(resp []byte, properties []PropertyTag) (int, error) {
	pos := 0
	queryRows.RopID, pos = readByte(pos, resp)
	queryRows.InputHandle, pos = readByte(pos, resp)
	queryRows.ReturnValue, pos = readUint32(pos, resp)
	if queryRows.ReturnValue != 0 {
		return pos, fmt.Errorf("Non-zero return value %d", queryRows.ReturnValue)
	}
	queryRows.Origin, pos = readByte(pos, resp)
	queryRows.RowCount, pos = readUint16(pos, resp)

	rows := make([][]PropertyRow, queryRows.RowCount)

	for k := 0; k < int(queryRows.RowCount); k++ {
		trow := PropertyRow{}
		trow.Flag, pos = readByte(pos, resp)
		for _, property := range properties {
			if property.PropertyType == PtypInteger32 {
				trow.ValueArray, pos = readBytes(pos, 2, resp)
				rows[k] = append(rows[k], trow)
			} else if property.PropertyType == PtypInteger64 {
				trow.ValueArray, pos = readBytes(pos, 8, resp)
				rows[k] = append(rows[k], trow)
			} else if property.PropertyType == PtypString {
				trow.ValueArray, pos = readUnicodeString(pos, resp)
				rows[k] = append(rows[k], trow)
				pos++
			} else if property.PropertyType == PtypBinary {
				cnt, p := readByte(pos, resp)
				pos = p
				trow.ValueArray, pos = readBytes(pos, int(cnt), resp)
				rows[k] = append(rows[k], trow)
			}
		}

	}

	queryRows.RowData = rows
	return pos, nil
}

//Unmarshal func
func (setColumnsResponse *RopSetColumnsResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0
	setColumnsResponse.RopID, pos = readByte(pos, resp)
	setColumnsResponse.InputHandle, pos = readByte(pos, resp)
	setColumnsResponse.ReturnValue, pos = readUint32(pos, resp)
	setColumnsResponse.TableStatus, pos = readByte(pos, resp)
	if setColumnsResponse.ReturnValue != 0 {
		return pos, fmt.Errorf("Non-zero return value %d", setColumnsResponse.ReturnValue)
	}
	return pos, nil
}

//Unmarshal function to produce RopLogonResponse struct
func (getRulesTable *RopGetRulesTableResponse) Unmarshal(resp []byte) (int, error) {
	var pos = 0
	getRulesTable.RopID, pos = readByte(pos, resp)
	getRulesTable.OutputHandle, pos = readByte(pos, resp)
	getRulesTable.ReturnValue, pos = readUint32(pos, resp)
	if getRulesTable.ReturnValue != 0 {
		return pos, fmt.Errorf("Non-zero return value %d", getRulesTable.ReturnValue)
	}

	return pos, nil
}

//Unmarshal func
func (ropOpenFolderResponse *RopOpenFolderResponse) Unmarshal(resp []byte) (int, error) {
	pos := 10
	ropOpenFolderResponse.RopID, pos = readByte(pos, resp)
	ropOpenFolderResponse.OutputHandle, pos = readByte(pos, resp)
	ropOpenFolderResponse.ReturnValue, pos = readUint32(pos, resp)

	if ropOpenFolderResponse.ReturnValue != 0x000000 {
		return pos, fmt.Errorf("Non-zero reponse value %d", ropOpenFolderResponse.ReturnValue)
	}

	ropOpenFolderResponse.HasRules, pos = readByte(pos, resp)
	ropOpenFolderResponse.IsGhosted, pos = readByte(pos, resp)

	if ropOpenFolderResponse.IsGhosted == 1 {
		ropOpenFolderResponse.ServerCount, pos = readUint16(pos, resp)
		ropOpenFolderResponse.CheapServerCount, pos = readUint16(pos, resp)
		ropOpenFolderResponse.Servers, pos = readASCIIString(pos, resp)
	}
	return pos, nil
}

//Unmarshal func
func (ropGetPropertiesSpecificResponse *RopGetPropertiesSpecificResponse) Unmarshal(resp []byte, columns []PropertyTag) (int, error) {
	pos := 0
	ropGetPropertiesSpecificResponse.RopID, pos = readByte(pos, resp)
	ropGetPropertiesSpecificResponse.InputHandleIndex, pos = readByte(pos, resp)
	ropGetPropertiesSpecificResponse.ReturnValue, pos = readUint32(pos, resp)

	if ropGetPropertiesSpecificResponse.ReturnValue != 0x000000 {
		return pos, fmt.Errorf("Non-zero reponse value %d", ropGetPropertiesSpecificResponse.ReturnValue)
	}
	var rows []PropertyRow
	for _, property := range columns {
		trow := PropertyRow{}
		trow.Flag, pos = readByte(pos, resp)
		if property.PropertyType == PtypInteger32 {
			trow.ValueArray, pos = readBytes(pos, 2, resp)
			rows = append(rows, trow)
		} else if property.PropertyType == PtypString {
			trow.ValueArray, pos = readUnicodeString(pos, resp)
			rows = append(rows, trow)
		} else if property.PropertyType == PtypBinary {
			cnt, p := readByte(pos, resp)
			pos = p
			trow.ValueArray, pos = readBytes(pos, int(cnt), resp)
			rows = append(rows, trow)
		}
	}
	ropGetPropertiesSpecificResponse.RowData = rows
	return pos, nil
}

//DecodeGetTableResponse function Unmarshals the various parts of a getproperties response (this includes the initial openfolder request)
//and returns the RopGetPropertiesSpecificResponse object to us, we can then cycle through the rows to view the values
//needs the list of columns that were supplied in the initial request.
func DecodeGetTableResponse(resp []byte, columns []PropertyTag) (*RopGetPropertiesSpecificResponse, error) {
	pos := 10

	var err error

	openFolderResp := RopOpenFolderResponse{}
	pos, err = openFolderResp.Unmarshal(resp)
	if err != nil {
		return nil, err
	}
	properties := RopGetPropertiesSpecificResponse{}
	_, err = properties.Unmarshal(resp[pos:], columns)

	if err != nil {
		return nil, err
	}

	return &properties, nil
}

//DecodeRulesResponse func
func DecodeRulesResponse(resp []byte, properties []PropertyTag) ([]Rule, []byte) {

	pos, tpos := 10, 0
	var err error

	rulesTableResponse := RopGetRulesTableResponse{}
	tpos, err = rulesTableResponse.Unmarshal(resp[pos:])
	pos += tpos

	if err != nil {
		fmt.Println(err)
		return nil, nil
	}
	columns := RopSetColumnsResponse{}
	tpos, err = columns.Unmarshal(resp[pos:])
	pos += tpos

	if err != nil {
		fmt.Println("Bad SetColumns")
		return nil, nil
	}

	rows := RopQueryRowsResponse{}
	tpos, err = rows.Unmarshal(resp[pos:], properties)
	if err != nil {
		fmt.Println("Bad QueryRows")
		return nil, nil
	}
	pos += tpos

	rules := make([]Rule, int(rows.RowCount))

	for k := 0; k < int(rows.RowCount); k++ {
		rule := Rule{}
		rule.RuleID = rows.RowData[k][0].ValueArray
		rule.RuleName = rows.RowData[k][1].ValueArray
		rules[k] = rule
	}
	ruleshandle := resp[pos+4:]

	return rules, ruleshandle
}
