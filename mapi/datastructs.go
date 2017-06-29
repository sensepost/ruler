package mapi

import (
	"github.com/sensepost/ruler/utils"
)

//ConnectRequest struct
type ConnectRequest struct {
	UserDN            []byte
	Flags             uint32
	DefaultCodePage   uint32
	LcidString        uint32
	LcidSort          uint32
	AuxilliaryBufSize uint32
	AuxilliaryBuf     []byte
}

//ConnectRequestRPC ConnectRequest structure for RPC
type ConnectRequestRPC struct {
	DNLen               uint32
	Reserved            uint32
	DNLenActual         uint32
	UserDN              []byte
	Flags               uint32
	DNHash              uint32
	CbLimit             uint32 //[]byte
	DefaultCodePage     uint32
	LcidString          uint32
	LcidSort            uint32
	IcxrLink            uint32
	FCanConvertCodePage uint16
	ClientVersion       []byte
	TimeStamp           uint32
	AuxilliaryBufSize   uint32
	AuxilliaryBuf       []byte
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
	RPCPtr            []byte
	AuxilliaryBufSize uint32
	AuxilliaryBuf     []byte
}

//ExecuteRequestRPC struct for RPC ExecuteRequest, slightly different from MAPI/HTTP
type ExecuteRequestRPC struct {
	Flags         uint32 //[]byte //lets stick to ropFlagsNoXorMagic
	RopBufferSize uint32
	RopBuffer     ROPBuffer
	MaxRopOut     uint32
}

//ExecuteResponse struct
type ExecuteResponse struct {
	StatusCode        uint32 //if 0x00000 --> failure and we only have AuzilliaryBufferSize and AuxilliaryBuffer
	ErrorCode         uint32
	Flags             uint32 //0x00000000 always
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

//RopGetRulesTableRequest struct
type RopGetRulesTableRequest struct {
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

//RopSetPropertiesRequest struct to set properties on an object
type RopSetPropertiesRequest struct {
	RopID             uint8 //0x0A
	LogonID           uint8
	InputHandle       uint8
	PropertValueSize  uint16
	PropertValueCount uint16
	PropertyValues    []TaggedPropertyValue
}

//RopSetPropertiesResponse struct to set properties on an object
type RopSetPropertiesResponse struct {
	RopID                uint8 //0x0A
	InputHandle          uint8
	ReturnValue          uint32
	PropertyProblemCount uint16
	PropertyProblems     []byte
}

//RopGetPropertiesSpecificResponse struct to get propertiesfor a folder
type RopGetPropertiesSpecificResponse struct {
	RopID             uint8 //0x07
	InputHandleIndex  uint8
	ReturnValue       uint32
	PropertySizeLimit uint16
	RowData           []PropertyRow
}

//RopFastTransferDestinationConfigureRequest used to configure a destination buffer for fast TransferBuffer
type RopFastTransferDestinationConfigureRequest struct {
	RopID           uint8 //0x53
	LogonID         uint8
	InputHandle     uint8
	OutputHandle    uint8
	SourceOperation uint8
	CopyFlags       uint8
}

//RopFastTransferDestinationConfigureResponse used to configure a destination buffer for fast TransferBuffer
type RopFastTransferDestinationConfigureResponse struct {
	RopID        uint8 //0x53
	OutputHandle uint8
	ReturnValue  uint32
}

//RopFastTransferDestinationPutBufferRequest to actually upload the data
type RopFastTransferDestinationPutBufferRequest struct {
	RopID            uint8 //0x53
	LogonID          uint8
	InputHandle      uint8
	TransferDataSize uint16
	TransferData     []byte
}

//RopOpenFolderRequest struct used to open a folder
type RopOpenFolderRequest struct {
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

//RopGetHierarchyTableRequest struct used to get folder hierarchy
type RopGetHierarchyTableRequest struct {
	RopID        uint8 //0x04
	LogonID      uint8
	InputHandle  uint8
	OutputHandle uint8
	TableFlags   uint8
}

//RopGetHierarchyTableResponse struct used to get folder hierarchy
type RopGetHierarchyTableResponse struct {
	RopID        uint8 //0x04
	OutputHandle uint8
	ReturnValue  uint32
	RowCount     uint32
}

//RopCreateFolderRequest struct used to create a folder
type RopCreateFolderRequest struct {
	RopID             uint8 //0x1C
	LogonID           uint8
	InputHandle       uint8
	OutputHandle      uint8
	FolderType        uint8
	UseUnicodeStrings uint8
	OpenExisting      uint8
	Reserved          uint8
	DisplayName       []byte
	Comment           []byte
}

//RopCreateFolderResponse struct used to create a folder
type RopCreateFolderResponse struct {
	RopID            uint8 //0x1C
	OutputHandle     uint8
	ReturnValue      uint32
	FolderID         []byte
	IsExisting       uint8
	HasRules         byte   //bool
	IsGhosted        byte   //bool
	ServerCount      uint16 //only if IsGhosted == true
	CheapServerCount uint16 //only if IsGhosted == true
	Servers          []byte //only if IsGhosted == true
}

//RopEmptyFolderRequest used to delete all messages and subfolders from a folder
type RopEmptyFolderRequest struct {
	RopID                uint8 //0x58
	LogonID              uint8
	InputHandle          uint8
	WantAsynchronous     uint8
	WantDeleteAssociated uint8
}

//RopEmptyFolderResponse to emptying a folder
type RopEmptyFolderResponse struct {
	RopID           uint8 //0x58
	InputHandle     uint8
	ReturnValue     uint32
	PartialComplete uint8
}

//RopDeleteFolderRequest used to delete a folder
type RopDeleteFolderRequest struct {
	RopID             uint8 //0x1D
	LogonID           uint8
	InputHandle       uint8
	DeleteFolderFlags uint8
	FolderID          []byte
}

//RopDeleteFolderResponse to delete a folder
type RopDeleteFolderResponse struct {
	RopID           uint8 //0x1D
	InputHandle     uint8
	ReturnValue     uint32
	PartialComplete uint8
}

//RopCreateMessageRequest struct used to open handle to new email message
type RopCreateMessageRequest struct {
	RopID          uint8 //0x32
	LogonID        uint8
	InputHandle    uint8
	OutputHandle   uint8
	CodePageID     uint16
	FolderID       []byte
	AssociatedFlag byte //bool
}

//RopSubmitMessageRequest struct used to open handle to new email message
type RopSubmitMessageRequest struct {
	RopID       uint8
	LogonID     uint8
	InputHandle uint8
	SubmitFlags uint8
}

//RopSubmitMessageResponse struct used to open handle to new email message
type RopSubmitMessageResponse struct {
	RopID       uint8
	InputHandle uint8
	ReturnValue uint32
}

//RopDeleteMessagesRequest struct used to delete one or more messages
type RopDeleteMessagesRequest struct {
	RopID           uint8 //0x1E
	LogonID         uint8
	InputHandle     uint8
	WantSynchronous uint8
	NotifyNonRead   uint8
	MessageIDCount  uint16
	MessageIDs      []byte //messageIdCount * 64 bit identifiers
}

//RopDeleteMessagesResponse struct holds response for deleting messages
type RopDeleteMessagesResponse struct {
	RopID             uint8
	InputHandle       uint8
	ReturnValue       uint32
	PartialCompletion uint8
}

//RopSaveChangesMessageRequest struct used to open handle to new email message
type RopSaveChangesMessageRequest struct {
	RopID               uint8
	LogonID             uint8
	ResponseHandleIndex uint8
	InputHandle         uint8
	SaveFlags           byte
}

//RopSaveChangesMessageResponse struct used to open handle to new email message
type RopSaveChangesMessageResponse struct {
	RopID               uint8
	ResponseHandleIndex uint8
	ReturnValue         uint32
	InputHandle         uint8
	MessageID           []byte
}

//RopGetAttachmentTableRequest to open the attachment table
type RopGetAttachmentTableRequest struct {
	RopID             uint8 //0x21
	LogonID           uint8
	InputHandleIndex  uint8
	OutputHandleIndex uint8
	TableFlags        uint8
}

//RopGetAttachmentTableResponse struct holding the attachment table index
type RopGetAttachmentTableResponse struct {
	RopID             uint8 //0x21
	OutputHandleIndex uint8
	ReturnValue       uint32
}

//RopOpenAttachmentRequest to open an existing attachment
type RopOpenAttachmentRequest struct {
	RopID               uint8 //0x22
	LogonID             uint8
	InputHandleIndex    uint8
	OutputHandleIndex   uint8
	OpenAttachmentFlags uint8
	AttachmentID        uint32
}

//RopOpenAttachmentResponse struct holding the attachment  index
type RopOpenAttachmentResponse struct {
	RopID             uint8 //0x22
	OutputHandleIndex uint8
	ReturnValue       uint32
}

//RopSynchronizationOpenCollectorRequest struct used to open handle to new email message
type RopSynchronizationOpenCollectorRequest struct {
	RopID               uint8
	LogonID             uint8
	InputHandle         uint8
	OutputHandle        uint8
	IsContentsCollector byte
}

//RopSynchronizationOpenCollectorResponse struct used to open handle to new email message
type RopSynchronizationOpenCollectorResponse struct {
	RopID        uint8
	OutputHandle uint8
	ReturnValue  uint32
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

//RopOpenMessageResponse struct used to open handle to  message
type RopOpenMessageResponse struct {
	RopID              uint8 //0x03
	OutputHandle       uint8
	ReturnValue        uint32
	HasNamedProperties byte
	SubjectPrefix      []byte
	NormalizedSubject  []byte
	RecipientCount     uint16
	ColumnCount        uint16
	RecipientColumns   []PropertyTag
	RowCount           uint8
	RecipientRows      []RecipientRow
}

//RopCreateAttachmentRequest used to create an attachment
type RopCreateAttachmentRequest struct {
	RopID             uint8 //0x23
	LogonID           uint8
	InputHandleIndex  uint8
	OutputHandleIndex uint8
}

//RopCreateAttachmentResponse holds the response to a create attachment
type RopCreateAttachmentResponse struct {
	RopID             uint8 //0x23
	OutputHandleIndex uint8
	ReturnValue       uint32
	AttachmentID      uint32
}

//RopSaveChangesAttachmentRequest used to create an attachment
type RopSaveChangesAttachmentRequest struct {
	RopID               uint8 //0x25
	LogonID             uint8
	InputHandleIndex    uint8
	ResponseHandleIndex uint8
	SaveFlags           uint8
}

//RopSaveChangesAttachmentResponse holds the response to a create attachment
type RopSaveChangesAttachmentResponse struct {
	RopID               uint8 //0x25
	ResponseHandleIndex uint8
	ReturnValue         uint32
}

//RopFastTransferSourceCopyToRequest struct used to open handle to  message
type RopFastTransferSourceCopyToRequest struct {
	RopID            uint8 //0x4D
	LogonID          uint8
	InputHandle      uint8
	OutputHandle     uint8
	Level            uint8
	CopyFlags        uint32
	SendOptions      uint8
	PropertyTagCount uint16
	PropertyTags     []PropertyTag
}

//RopFastTransferSourceCopyPropertiesRequest struct used to open handle to  message
type RopFastTransferSourceCopyPropertiesRequest struct {
	RopID            uint8 //0x69
	LogonID          uint8
	InputHandle      uint8
	OutputHandle     uint8
	Level            uint8
	CopyFlags        uint8
	SendOptions      uint8
	PropertyTagCount uint16
	PropertyTags     []PropertyTag
}

//RopFastTransferSourceGetBufferRequest struct used to open handle to  message
type RopFastTransferSourceGetBufferRequest struct {
	RopID             uint8 //0x4E
	LogonID           uint8
	InputHandle       uint8
	BufferSize        uint16
	MaximumBufferSize uint16 //0xBABE
}

//RopFastTransferSourceCopyPropertiesResponse struct used to open handle to  message
type RopFastTransferSourceCopyPropertiesResponse struct {
	RopID       uint8 //0x4E
	InputHandle uint8
	ReturnValue uint32
}

//RopFastTransferSourceGetBufferResponse struct used to open handle to  message
type RopFastTransferSourceGetBufferResponse struct {
	RopID                   uint8 //0x4E
	InputHandle             uint8
	ReturnValue             uint32
	TransferStatus          uint16
	InProgressCount         uint16
	TotalStepCount          uint16
	Reserved                uint8 //0x00
	TotalTransferBufferSize uint16
	TransferBuffer          []byte
	BackoffTime             uint32
}

//RopOpenStreamRequest struct used to open a stream
type RopOpenStreamRequest struct {
	RopID             uint8 //0x2B
	LogonID           uint8
	InputHandleIndex  uint8
	OutputHandleIndex uint8
	PropertyTag       PropertyTag
	OpenModeFlags     uint8
}

//RopOpenStreamResponse struct used to open a stream
type RopOpenStreamResponse struct {
	RopID             uint8 //0x2B
	OutputHandleIndex uint8
	ReturnValue       uint32
	StreamSize        uint32
}

//RopWriteStreamRequest struct used to write a stream
type RopWriteStreamRequest struct {
	RopID            uint8 //0x2B
	LogonID          uint8
	InputHandleIndex uint8
	DataSize         uint16
	Data             []byte
}

//RopWriteStreamResponse struct used to write a stream
type RopWriteStreamResponse struct {
	RopID            uint8 //0x2B
	InputHandleIndex uint8
	ReturnValue      uint32
	WrittenSize      uint16
}

//RopCommitStreamRequest struct used to commit a stream
type RopCommitStreamRequest struct {
	RopID            uint8 //0x2B
	LogonID          uint8
	InputHandleIndex uint8
}

//RopCommitStreamResponse struct used to commit a stream
type RopCommitStreamResponse struct {
	RopID            uint8 //0x2B
	InputHandleIndex uint8
	ReturnValue      uint32
}

//RopSetStreamSizeRequest struct used to open a stream
type RopSetStreamSizeRequest struct {
	RopID            uint8 //0x2F
	LogonID          uint8
	InputHandleIndex uint8
	StreamSize       uint64
}

//RopSetStreamSizeResponse struct used to open a stream
type RopSetStreamSizeResponse struct {
	RopID             uint8 //0x2B
	OutputHandleIndex uint8
	ReturnValue       uint32
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

//RopSetMessageStatusRequest struct used to select the columns to use
type RopSetMessageStatusRequest struct {
	RopID              uint8 //0x20
	LogonID            uint8
	InputHandle        uint8
	MessageID          []byte
	MessageStatusFlags PropertyTag
	MessageStatusMask  uint32
}

//RopSetMessageStatusResponse struct used to select the columns to use
type RopSetMessageStatusResponse struct {
	RopID              uint8 //0x20
	InputHandle        uint8
	ReturnValue        uint32
	MessageStatusFlags uint32
}

//RopReleaseRequest struct used to release all resources associated with a server object
type RopReleaseRequest struct {
	RopID       uint8 //0x01
	LogonID     uint8
	InputHandle uint8
}

//RopReleaseResponse struct used to release all resources associated with a server object
type RopReleaseResponse struct {
	RopID       uint8 //0x01
	ReturnValue uint32
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

//RopModifyRecipientsRequest to modify who is receiving email
type RopModifyRecipientsRequest struct {
	RopID            uint8 //0x0E
	LogonID          uint8
	InputHandle      uint8
	ColumnCount      uint16
	RecipientColumns []PropertyTag
	RowCount         uint16
	RecipientRows    []ModifyRecipientRow
}

//RopModifyRecipientsResponse to modify who is receiving email
type RopModifyRecipientsResponse struct {
	RopID       uint8 //0x0E
	InputHandle uint8
	ReturnValue uint32
}

//ModifyRecipientRow contains information about a recipient
type ModifyRecipientRow struct {
	RowID            uint32
	RecipientType    uint8
	RecipientRowSize uint16
	RecipientRow     RecipientRow
}

//RecipientRow holds a recipient of a mail message
type RecipientRow struct {
	RecipientFlags uint16
	//AddressPrefixUsed    uint8
	//DisplayType          uint8
	EmailAddress         []byte
	DisplayName          []byte
	SimpleDisplayName    []byte
	RecipientColumnCount uint16
	RecipientProperties  StandardPropertyRow
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
	Trigger []byte
	Elem    []byte
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

//StandardPropertyRow struct
type StandardPropertyRow struct {
	Flag       uint8
	ValueArray [][]byte
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

//Request interface type
type Request interface {
	Marshal() []byte
}

//Marshal turn ExecuteRequest into Bytes
func (execRequest ExecuteRequest) Marshal() []byte {
	execRequest.CalcSizes(false)
	return utils.BodyToBytes(execRequest)
}

//MarshalRPC turn ExecuteRequest into Bytes
func (execRequest ExecuteRequest) MarshalRPC() []byte {
	execRequest.CalcSizes(true)
	return utils.BodyToBytes(execRequest)
}

//Marshal turn ExecuteRequest into Bytes
func (execRequest ExecuteRequestRPC) Marshal() []byte {
	//execRequest.CalcSizes()
	return utils.BodyToBytes(execRequest)
}

//Marshal turn ConnectRequest into Bytes
func (connRequest ConnectRequest) Marshal() []byte {
	return utils.BodyToBytes(connRequest)
}

//Marshal turn ConnectRequest into Bytes
func (connRequest ConnectRequestRPC) Marshal() []byte {
	return utils.BodyToBytes(connRequest)
}

//Marshal turn DisconnectRequest into Bytes
func (disconnectRequest DisconnectRequest) Marshal() []byte {
	return utils.BodyToBytes(disconnectRequest)
}

//Marshal turn RopLogonRequest into Bytes
func (logonRequest RopLogonRequest) Marshal() []byte {
	return utils.BodyToBytes(logonRequest)
}

//Marshal turn the RopQueryRowsRequest into bytes
func (queryRows RopQueryRowsRequest) Marshal() []byte {
	return utils.BodyToBytes(queryRows)
}

//Marshal to turn the RopSetColumnsRequest into bytes
func (setColumns RopSetColumnsRequest) Marshal() []byte {
	return utils.BodyToBytes(setColumns)
}

//Marshal turn RopOpenFolder into Bytes
func (openFolder RopOpenFolderRequest) Marshal() []byte {
	return utils.BodyToBytes(openFolder)
}

//Marshal turn RopSetMessageStatusRequest into Bytes
func (setStatus RopSetMessageStatusRequest) Marshal() []byte {
	return utils.BodyToBytes(setStatus)
}

//Marshal turn RopCreateFolderRequest into Bytes
func (createFolder RopCreateFolderRequest) Marshal() []byte {
	return utils.BodyToBytes(createFolder)
}

//Marshal turn RopGetHierarchyTableRequest into Bytes
func (getHierarchy RopGetHierarchyTableRequest) Marshal() []byte {
	return utils.BodyToBytes(getHierarchy)
}

//Marshal turn RopFastTransferSourceCopyToRequest into Bytes
func (getProps RopFastTransferSourceCopyToRequest) Marshal() []byte {
	return utils.BodyToBytes(getProps)
}

//Marshal turn RopFastTransferSourceCopyPropertiesRequest into Bytes
func (getProps RopFastTransferSourceCopyPropertiesRequest) Marshal() []byte {
	return utils.BodyToBytes(getProps)
}

//Marshal turn RopFastTransferSourceGetBufferRequest into Bytes
func (getBuff RopFastTransferSourceGetBufferRequest) Marshal() []byte {
	return utils.BodyToBytes(getBuff)
}

//Marshal turn RopFastTransferDestinationConfigureRequest into Bytes
func (getBuff RopFastTransferDestinationConfigureRequest) Marshal() []byte {
	return utils.BodyToBytes(getBuff)
}

//Marshal turn RopFastTransferDestinationConfigureRequest into Bytes
func (getBuff RopFastTransferDestinationPutBufferRequest) Marshal() []byte {
	return utils.BodyToBytes(getBuff)
}

//Marshal turn RopGetPropertiesSpecific into Bytes
func (getProps RopGetPropertiesSpecific) Marshal() []byte {
	return utils.BodyToBytes(getProps)
}

//Marshal turn RopGetContentsTableRequest into Bytes
func (getContentsTable RopGetContentsTableRequest) Marshal() []byte {
	return utils.BodyToBytes(getContentsTable)
}

//Marshal turn RopGetRulesTableRequest into Bytes
func (getRules RopGetRulesTableRequest) Marshal() []byte {
	return utils.BodyToBytes(getRules)
}

//Marshal turn ExecuteRequest into Bytes
func (createMessage RopCreateMessageRequest) Marshal() []byte {
	return utils.BodyToBytes(createMessage)
}

//Marshal turn ExecuteRequest into Bytes
func (deleteMessage RopDeleteMessagesRequest) Marshal() []byte {
	return utils.BodyToBytes(deleteMessage)
}

//Marshal turn RopSetPropertiesRequest into Bytes
func (setProperties RopSetPropertiesRequest) Marshal() []byte {
	return utils.BodyToBytes(setProperties)
}

//Marshal turn  RopSaveChangesMessageRequest into Bytes
func (saveMessage RopSaveChangesMessageRequest) Marshal() []byte {
	return utils.BodyToBytes(saveMessage)
}

//Marshal turn RopOpenMessageRequest into Bytes
func (openMessage RopOpenMessageRequest) Marshal() []byte {
	return utils.BodyToBytes(openMessage)
}

//Marshal turn RopSubmitMessageRequest into Bytes
func (submitMessage RopSubmitMessageRequest) Marshal() []byte {
	return utils.BodyToBytes(submitMessage)
}

//Marshal turn RopSynchronizationOpenCollectorRequest into Bytes
func (syncRop RopSynchronizationOpenCollectorRequest) Marshal() []byte {
	return utils.BodyToBytes(syncRop)
}

//Marshal turn RopOpenStreamRequest into Bytes
func (openStream RopOpenStreamRequest) Marshal() []byte {
	return utils.BodyToBytes(openStream)
}

//Marshal turn RopOpenStreamRequest into Bytes
func (setStreamSize RopSetStreamSizeRequest) Marshal() []byte {
	return utils.BodyToBytes(setStreamSize)
}

//Marshal turn RopOpenStreamRequest into Bytes
func (writeStream RopWriteStreamRequest) Marshal() []byte {
	return utils.BodyToBytes(writeStream)
}

//Marshal turn RopOpenStreamRequest into Bytes
func (commitStream RopCommitStreamRequest) Marshal() []byte {
	return utils.BodyToBytes(commitStream)
}

//Marshal turn RopReadStreamRequest into Bytes
func (readStream RopReadStreamRequest) Marshal() []byte {
	return utils.BodyToBytes(readStream)
}

//Marshal turn RuleAction into Bytes
func (ruleAction RuleAction) Marshal() []byte {
	return utils.BodyToBytes(ruleAction)
}

//Marshal turn RopReleaseRequest into Bytes
func (releaseRequest RopReleaseRequest) Marshal() []byte {
	return utils.BodyToBytes(releaseRequest)
}

//Marshal turn RopModifyRecipientsRequest into Bytes
func (modRecipients RopModifyRecipientsRequest) Marshal() []byte {
	return utils.BodyToBytes(modRecipients)
}

//Marshal turn RopFastTransferSourceCopyPropertiesRequest into Bytes
func (emptyFolder RopEmptyFolderRequest) Marshal() []byte {
	return utils.BodyToBytes(emptyFolder)
}

//Marshal turn RopDeleteFolderRequest into Bytes
func (deleteFolder RopDeleteFolderRequest) Marshal() []byte {
	return utils.BodyToBytes(deleteFolder)
}

//Marshal turn RopGetAttachmentTableRequest into Bytes
func (getAttachTable RopGetAttachmentTableRequest) Marshal() []byte {
	return utils.BodyToBytes(getAttachTable)
}

//Marshal turn RopCreateAttachmentRequest into Bytes
func (createAttach RopCreateAttachmentRequest) Marshal() []byte {
	return utils.BodyToBytes(createAttach)
}

//Marshal turn RopOpenAttachmentRequest into Bytes
func (getAttach RopOpenAttachmentRequest) Marshal() []byte {
	return utils.BodyToBytes(getAttach)
}

//Marshal turn RopSaveChangesAttachmentRequest into Bytes
func (saveAttach RopSaveChangesAttachmentRequest) Marshal() []byte {
	return utils.BodyToBytes(saveAttach)
}

//Unmarshal function to convert response into ConnectResponse struct
func (connResponse *ConnectResponse) Unmarshal(resp []byte) error {
	pos := 0
	connResponse.StatusCode, pos = utils.ReadUint32(pos, resp)
	if connResponse.StatusCode != 0 { //error occurred..
		connResponse.AuxilliaryBufferSize, pos = utils.ReadUint32(pos, resp)
		connResponse.AuxilliaryBuffer = resp[8 : 8+connResponse.AuxilliaryBufferSize]
	} else {
		connResponse.ErrorCode, pos = utils.ReadUint32(pos, resp)
		connResponse.PollsMax, pos = utils.ReadUint32(pos, resp)
		connResponse.RetryCount, pos = utils.ReadUint32(pos, resp)
		connResponse.RetryDelay, pos = utils.ReadUint32(pos, resp)
		connResponse.DNPrefix, pos = utils.ReadUnicodeString(pos, resp)
		connResponse.DisplayName, pos = utils.ReadASCIIString(pos, resp)
		connResponse.AuxilliaryBufferSize, pos = utils.ReadUint32(pos, resp)
		connResponse.AuxilliaryBuffer = resp[pos:]
	}
	return nil
}

//Unmarshal function to produce RopLogonResponse struct
func (logonResponse *RopLogonResponse) Unmarshal(resp []byte) error {
	pos := 10
	logonResponse.RopID, pos = utils.ReadByte(pos, resp)
	logonResponse.OutputHandleIndex, pos = utils.ReadByte(pos, resp)
	logonResponse.ReturnValue, pos = utils.ReadUint32(pos, resp)
	if logonResponse.ReturnValue != 0 {
		return &ErrorCode{logonResponse.ReturnValue}
	}
	logonResponse.LogonFlags, pos = utils.ReadByte(pos, resp)
	logonResponse.FolderIds, pos = utils.ReadBytes(pos, 104, resp)
	logonResponse.ResponseFlags, pos = utils.ReadByte(pos, resp)
	logonResponse.MailboxGUID, pos = utils.ReadBytes(pos, 16, resp)
	logonResponse.RepID, pos = utils.ReadBytes(pos, 2, resp)
	logonResponse.ReplGUID, pos = utils.ReadBytes(pos, 16, resp)
	logonResponse.LogonTime, pos = utils.ReadBytes(pos, 8, resp)
	logonResponse.GwartTime, pos = utils.ReadBytes(pos, 8, resp)
	logonResponse.StoreState, _ = utils.ReadBytes(pos, 4, resp)
	return nil
}

//Unmarshal for ExecuteResponse
//the output seems to vary for MAPIHTTP and RPC
//MAPIHTTP StatusCode,ErrorCode,Flags,RopBufferSize
//RPC StatusCode,RopBufferSize,Flags,RopBufferSize
func (execResponse *ExecuteResponse) Unmarshal(resp []byte) error {
	pos := 0
	var buf []byte

	execResponse.StatusCode, pos = utils.ReadUint32(pos, resp)

	//for MAPIHTTP, none-zero value indicates error. Should be same for RPC/HTTP but have encountered servers that return value 3
	if execResponse.StatusCode == 255 { //error occurred..
		execResponse.AuxilliaryBufSize, pos = utils.ReadUint32(pos, resp)
		execResponse.AuxilliaryBuf = resp[8 : 8+execResponse.AuxilliaryBufSize]
	} else {
		execResponse.ErrorCode, pos = utils.ReadUint32(pos, resp) //error code if MAPIHTTP else this is also the buffer size
		execResponse.Flags, pos = utils.ReadUint32(pos, resp)
		execResponse.RopBufferSize, pos = utils.ReadUint32(pos, resp)
		if len(resp) < pos+int(execResponse.RopBufferSize) {
			return nil
		}
		buf, pos = utils.ReadBytes(pos, int(execResponse.RopBufferSize), resp)
		execResponse.RopBuffer = buf
		execResponse.AuxilliaryBufSize, _ = utils.ReadUint32(pos, resp)
		//execResponse.AuxilliaryBuf, _ = utils.ReadBytes(pos, int(execResponse.AuxilliaryBufSize), resp)
	}
	return nil
}

//Unmarshal func
func (ropRelease *RopReleaseResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0
	ropRelease.RopID, pos = utils.ReadByte(pos, resp)
	ropRelease.ReturnValue, pos = utils.ReadUint32(pos, resp)
	if ropRelease.ReturnValue != 0 {
		return pos, &ErrorCode{ropRelease.ReturnValue}
	}
	return pos, nil
}

//Unmarshal func
func (ropContents *RopGetContentsTableResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0
	ropContents.RopID, pos = utils.ReadByte(pos, resp)
	ropContents.OutputHandle, pos = utils.ReadByte(pos, resp)
	ropContents.ReturnValue, pos = utils.ReadUint32(pos, resp)
	if ropContents.ReturnValue != 0 {
		return pos, &ErrorCode{ropContents.ReturnValue}
	}
	ropContents.RowCount, pos = utils.ReadUint32(pos, resp)
	return pos, nil
}

//Unmarshal func
func (setStatus *RopSetMessageStatusResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0
	setStatus.RopID, pos = utils.ReadByte(pos, resp)
	setStatus.InputHandle, pos = utils.ReadByte(pos, resp)
	setStatus.ReturnValue, pos = utils.ReadUint32(pos, resp)
	if setStatus.ReturnValue != 0 {
		return pos, &ErrorCode{setStatus.ReturnValue}
	}
	setStatus.MessageStatusFlags, pos = utils.ReadUint32(pos, resp)
	return pos, nil
}

//Unmarshal func for RopCreateFolderResponse
func (createFolder *RopCreateFolderResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0
	createFolder.RopID, pos = utils.ReadByte(pos, resp)
	createFolder.OutputHandle, pos = utils.ReadByte(pos, resp)
	createFolder.ReturnValue, pos = utils.ReadUint32(pos, resp)
	if createFolder.ReturnValue != 0 {
		return pos, &ErrorCode{createFolder.ReturnValue}
	}

	return pos, nil
}

//Unmarshal function to produce RopCreateMessageResponse struct
func (createMessageResponse *RopCreateMessageResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0

	createMessageResponse.RopID, pos = utils.ReadByte(pos, resp)
	createMessageResponse.OutputHandle, pos = utils.ReadByte(pos, resp)
	createMessageResponse.ReturnValue, pos = utils.ReadUint32(pos, resp)

	if createMessageResponse.ReturnValue == 0 {
		createMessageResponse.HasMessageID, pos = utils.ReadByte(pos, resp)
		if createMessageResponse.HasMessageID == 1 {
			createMessageResponse.MessageID, _ = utils.ReadBytes(pos, 8, resp)

		}
	} else {
		return pos, &ErrorCode{createMessageResponse.ReturnValue}
	}
	return pos, nil
}

//Unmarshal function to produce RopDeleteMessagesResponse struct
func (deleteMessageResponse *RopDeleteMessagesResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0

	deleteMessageResponse.RopID, pos = utils.ReadByte(pos, resp)
	deleteMessageResponse.InputHandle, pos = utils.ReadByte(pos, resp)
	deleteMessageResponse.ReturnValue, pos = utils.ReadUint32(pos, resp)
	deleteMessageResponse.PartialCompletion, pos = utils.ReadByte(pos, resp)
	if deleteMessageResponse.ReturnValue != 0 {
		return pos, &ErrorCode{deleteMessageResponse.ReturnValue}
	}
	return pos, nil
}

//Unmarshal function to produce RopEmptyFolderResponse struct
func (emptyFolderResponse *RopEmptyFolderResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0

	emptyFolderResponse.RopID, pos = utils.ReadByte(pos, resp)
	emptyFolderResponse.InputHandle, pos = utils.ReadByte(pos, resp)
	emptyFolderResponse.ReturnValue, pos = utils.ReadUint32(pos, resp)
	emptyFolderResponse.PartialComplete, pos = utils.ReadByte(pos, resp)
	if emptyFolderResponse.ReturnValue != 0 {
		return pos, &ErrorCode{emptyFolderResponse.ReturnValue}
	}
	return pos, nil
}

//Unmarshal function to produce RopDeleteFolderResponse struct
func (deleteFolderResponse *RopDeleteFolderResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0

	deleteFolderResponse.RopID, pos = utils.ReadByte(pos, resp)
	deleteFolderResponse.InputHandle, pos = utils.ReadByte(pos, resp)
	deleteFolderResponse.ReturnValue, pos = utils.ReadUint32(pos, resp)
	deleteFolderResponse.PartialComplete, pos = utils.ReadByte(pos, resp)
	if deleteFolderResponse.ReturnValue != 0 {
		return pos, &ErrorCode{deleteFolderResponse.ReturnValue}
	}
	return pos, nil
}

//Unmarshal function to produce RopCreateMessageResponse struct
func (modRecipientsResponse *RopModifyRecipientsResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0

	modRecipientsResponse.RopID, pos = utils.ReadByte(pos, resp)
	modRecipientsResponse.InputHandle, pos = utils.ReadByte(pos, resp)
	modRecipientsResponse.ReturnValue, pos = utils.ReadUint32(pos, resp)

	if modRecipientsResponse.ReturnValue != 0 {
		return pos, &ErrorCode{modRecipientsResponse.ReturnValue}
	}
	return pos, nil
}

//Unmarshal function to produce RopSynchronizationOpenCollectorResponse struct
func (syncResponse *RopSynchronizationOpenCollectorResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0

	syncResponse.RopID, pos = utils.ReadByte(pos, resp)
	syncResponse.OutputHandle, pos = utils.ReadByte(pos, resp)
	syncResponse.ReturnValue, pos = utils.ReadUint32(pos, resp)

	if syncResponse.ReturnValue != 0 {
		return pos, &ErrorCode{syncResponse.ReturnValue}
	}
	return pos, nil
}

//Unmarshal function to produce RopCreateMessageResponse struct
func (submitMessageResp *RopSubmitMessageResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0

	submitMessageResp.RopID, pos = utils.ReadByte(pos, resp)
	submitMessageResp.InputHandle, pos = utils.ReadByte(pos, resp)
	submitMessageResp.ReturnValue, pos = utils.ReadUint32(pos, resp)

	if submitMessageResp.ReturnValue != 0 {
		return pos, &ErrorCode{submitMessageResp.ReturnValue}
	}
	return pos, nil
}

//Unmarshal function to produce RopCreateMessageResponse struct
func (setPropertiesResponse *RopSetPropertiesResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0

	setPropertiesResponse.RopID, pos = utils.ReadByte(pos, resp)
	setPropertiesResponse.InputHandle, pos = utils.ReadByte(pos, resp)
	setPropertiesResponse.ReturnValue, pos = utils.ReadUint32(pos, resp)

	if setPropertiesResponse.ReturnValue == 0 {
		setPropertiesResponse.PropertyProblemCount, pos = utils.ReadUint16(pos, resp)
		if setPropertiesResponse.PropertyProblemCount > 0 {
			//fmt.Println(setPropertiesResponse.PropertProblemCount)
		}
	} else {
		return pos, &ErrorCode{setPropertiesResponse.ReturnValue}
	}
	return pos, nil
}

//Unmarshal function to produce RopCreateMessageResponse struct
func (getPropertiesResponse *RopFastTransferSourceCopyPropertiesResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0

	getPropertiesResponse.RopID, pos = utils.ReadByte(pos, resp)
	getPropertiesResponse.InputHandle, pos = utils.ReadByte(pos, resp)
	getPropertiesResponse.ReturnValue, pos = utils.ReadUint32(pos, resp)

	if getPropertiesResponse.ReturnValue != 0 {
		return pos, &ErrorCode{getPropertiesResponse.ReturnValue}
	}
	return pos, nil
}

//Unmarshal function to produce RopFastTransferSourceGetBufferResponse struct
func (buffResponse *RopFastTransferSourceGetBufferResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0

	buffResponse.RopID, pos = utils.ReadByte(pos, resp)
	buffResponse.InputHandle, pos = utils.ReadByte(pos, resp)
	buffResponse.ReturnValue, pos = utils.ReadUint32(pos, resp)

	if buffResponse.ReturnValue == 0 {
		buffResponse.TransferStatus, pos = utils.ReadUint16(pos, resp)
		buffResponse.InProgressCount, pos = utils.ReadUint16(pos, resp)
		buffResponse.TotalStepCount, pos = utils.ReadUint16(pos, resp)
		buffResponse.Reserved, pos = utils.ReadByte(pos, resp)
		buffResponse.TotalTransferBufferSize, pos = utils.ReadUint16(pos, resp)
		buffResponse.TransferBuffer, pos = utils.ReadBytes(pos, int(buffResponse.TotalTransferBufferSize), resp)
		buffResponse.BackoffTime, pos = utils.ReadUint32(pos, resp)
	} else {
		return pos, &ErrorCode{buffResponse.ReturnValue}
	}
	return pos, nil
}

//Unmarshal function to produce RopSaveChangesMessageResponse struct
func (saveMessageResponse *RopSaveChangesMessageResponse) Unmarshal(resp []byte) error {
	pos := 0

	saveMessageResponse.RopID, pos = utils.ReadByte(pos, resp)
	saveMessageResponse.ResponseHandleIndex, pos = utils.ReadByte(pos, resp)
	saveMessageResponse.ReturnValue, pos = utils.ReadUint32(pos, resp)

	if saveMessageResponse.ReturnValue == 0 {
		saveMessageResponse.InputHandle, pos = utils.ReadByte(pos, resp)
		saveMessageResponse.MessageID, _ = utils.ReadBytes(pos, 8, resp)
	}
	return nil
}

//CalcSizes func to calculate the different size fields in the ROP buffer
func (execRequest *ExecuteRequest) CalcSizes(isRPC bool) error {
	if !isRPC {
		execRequest.RopBuffer.ROP.RopSize = uint16(len(execRequest.RopBuffer.ROP.RopsList) + 2)
		execRequest.RopBuffer.Header.Size = uint16(len(utils.BodyToBytes(execRequest.RopBuffer.ROP)))
		execRequest.RopBuffer.Header.SizeActual = execRequest.RopBuffer.Header.Size
		execRequest.RopBufferSize = uint32(len(utils.BodyToBytes(execRequest.RopBuffer)))
	} else {
		padding := uint32(len(utils.BodyToBytes(execRequest.RopBuffer))) - execRequest.MaxRopOut
		execRequest.RopBuffer.ROP.RopSize = uint16(len(execRequest.RopBuffer.ROP.RopsList) + 2)
		execRequest.RopBuffer.Header.Size = uint16(len(utils.BodyToBytes(execRequest.RopBuffer.ROP)) - int(padding))
		execRequest.RopBuffer.Header.SizeActual = execRequest.RopBuffer.Header.Size
		execRequest.RopBufferSize = execRequest.MaxRopOut
	}
	return nil
}

//Init function to create a base ExecuteRequest object
func (execRequest *ExecuteRequest) Init() {
	execRequest.Flags = 0x00000002 | 0x00000001
	execRequest.RopBuffer.Header.Version = 0x0000
	execRequest.RopBuffer.Header.Flags = ropFlagsChain //[]byte{0x04, 0x00}
	execRequest.MaxRopOut = 23041                      //2634022912                 //23041                      //262143
}

//Unmarshal func
func (queryRows *RopQueryRowsResponse) Unmarshal(resp []byte, properties []PropertyTag) (int, error) {
	pos := 0
	var flag byte
	queryRows.RopID, pos = utils.ReadByte(pos, resp)
	queryRows.InputHandle, pos = utils.ReadByte(pos, resp)
	queryRows.ReturnValue, pos = utils.ReadUint32(pos, resp)
	if queryRows.ReturnValue != 0 {
		return pos, &ErrorCode{queryRows.ReturnValue}
	}
	queryRows.Origin, pos = utils.ReadByte(pos, resp)
	queryRows.RowCount, pos = utils.ReadUint16(pos, resp)

	rows := make([][]PropertyRow, queryRows.RowCount)
	//check if flagged properties

	for k := 0; k < int(queryRows.RowCount); k++ {
		trow := PropertyRow{}
		//check if has flag (is flaggedpropertyrow)
		flag, pos = utils.ReadByte(pos, resp)
		for _, property := range properties {

			if flag == 0x01 {
				trow.Flag, pos = utils.ReadByte(pos, resp)
			}
			if trow.Flag != 0x00 {
				trow.ValueArray, pos = utils.ReadBytes(pos, 4, resp)
				rows[k] = append(rows[k], trow)
			} else if property.PropertyType == PtypInteger32 {
				trow.ValueArray, pos = utils.ReadBytes(pos, 2, resp)
				rows[k] = append(rows[k], trow)
			} else if property.PropertyType == PtypInteger64 {
				trow.ValueArray, pos = utils.ReadBytes(pos, 8, resp)
				rows[k] = append(rows[k], trow)
			} else if property.PropertyType == PtypString {
				trow.ValueArray, pos = utils.ReadUnicodeString(pos, resp)
				rows[k] = append(rows[k], trow)
				if len(trow.ValueArray) > 0 { //empty string means no extra null byte.
					pos++
				}
			} else if property.PropertyType == PtypBinary {
				cnt, p := utils.ReadUint16(pos, resp)
				pos = p
				trow.ValueArray, pos = utils.ReadBytes(pos, int(cnt), resp)
				rows[k] = append(rows[k], trow)
			} else if property.PropertyType == PtypRuleAction {
				//Unmarshal the ruleaction and then add it into the ValueArray again. messy
				//or grab the action len, which is the second uint16 and use this to determine how much to read
				//read ahead to get the length
				_, pos = utils.ReadUint16(pos, resp)
				//read length but don't advance the buffer
				l, _ := utils.ReadUint16(pos, resp)
				//read the whole RuleAction into the valueArray, this means
				pos -= 2 //reset the position
				trow.ValueArray, pos = utils.ReadBytes(pos, int(l+4), resp)
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
	setColumnsResponse.RopID, pos = utils.ReadByte(pos, resp)
	setColumnsResponse.InputHandle, pos = utils.ReadByte(pos, resp)
	setColumnsResponse.ReturnValue, pos = utils.ReadUint32(pos, resp)
	setColumnsResponse.TableStatus, pos = utils.ReadByte(pos, resp)
	if setColumnsResponse.ReturnValue != 0 {
		return pos, &ErrorCode{setColumnsResponse.ReturnValue}
	}
	return pos, nil
}

//Unmarshal function to produce RopLogonResponse struct
func (getRulesTable *RopGetRulesTableResponse) Unmarshal(resp []byte) (int, error) {
	var pos = 0
	getRulesTable.RopID, pos = utils.ReadByte(pos, resp)
	getRulesTable.OutputHandle, pos = utils.ReadByte(pos, resp)
	getRulesTable.ReturnValue, pos = utils.ReadUint32(pos, resp)
	if getRulesTable.ReturnValue != 0 {
		return pos, &ErrorCode{getRulesTable.ReturnValue}
	}

	return pos, nil
}

//Unmarshal func
func (ropOpenFolderResponse *RopOpenFolderResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0
	ropOpenFolderResponse.RopID, pos = utils.ReadByte(pos, resp)
	ropOpenFolderResponse.OutputHandle, pos = utils.ReadByte(pos, resp)
	ropOpenFolderResponse.ReturnValue, pos = utils.ReadUint32(pos, resp)

	if ropOpenFolderResponse.ReturnValue != 0x000000 {
		return pos, &ErrorCode{ropOpenFolderResponse.ReturnValue}
	}

	ropOpenFolderResponse.HasRules, pos = utils.ReadByte(pos, resp)
	ropOpenFolderResponse.IsGhosted, pos = utils.ReadByte(pos, resp)

	if ropOpenFolderResponse.IsGhosted == 1 {
		ropOpenFolderResponse.ServerCount, pos = utils.ReadUint16(pos, resp)
		ropOpenFolderResponse.CheapServerCount, pos = utils.ReadUint16(pos, resp)
		ropOpenFolderResponse.Servers, pos = utils.ReadASCIIString(pos, resp)
	}

	return pos, nil
}

//Unmarshal function to produce RopCreateMessageResponse struct
func (getAttachmentTable *RopGetAttachmentTableResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0

	getAttachmentTable.RopID, pos = utils.ReadByte(pos, resp)
	getAttachmentTable.OutputHandleIndex, pos = utils.ReadByte(pos, resp)
	getAttachmentTable.ReturnValue, pos = utils.ReadUint32(pos, resp)

	if getAttachmentTable.ReturnValue != 0 {
		return pos, &ErrorCode{getAttachmentTable.ReturnValue}
	}
	return pos, nil
}

//Unmarshal function to produce RopCreateMessageResponse struct
func (createAttachment *RopCreateAttachmentResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0

	createAttachment.RopID, pos = utils.ReadByte(pos, resp)
	createAttachment.OutputHandleIndex, pos = utils.ReadByte(pos, resp)
	createAttachment.ReturnValue, pos = utils.ReadUint32(pos, resp)

	if createAttachment.ReturnValue != 0 {
		return pos, &ErrorCode{createAttachment.ReturnValue}
	}
	createAttachment.AttachmentID, pos = utils.ReadUint32(pos, resp)
	return pos, nil
}

//Unmarshal function to produce RopCreateMessageResponse struct
func (getAttachment *RopOpenAttachmentResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0

	getAttachment.RopID, pos = utils.ReadByte(pos, resp)
	getAttachment.OutputHandleIndex, pos = utils.ReadByte(pos, resp)
	getAttachment.ReturnValue, pos = utils.ReadUint32(pos, resp)

	if getAttachment.ReturnValue != 0 {
		return pos, &ErrorCode{getAttachment.ReturnValue}
	}

	return pos, nil
}

//Unmarshal function to produce RopSaveChangesMessageResponse struct
func (saveAttachResponse *RopSaveChangesAttachmentResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0

	saveAttachResponse.RopID, pos = utils.ReadByte(pos, resp)
	saveAttachResponse.ResponseHandleIndex, pos = utils.ReadByte(pos, resp)
	saveAttachResponse.ReturnValue, pos = utils.ReadUint32(pos, resp)

	if saveAttachResponse.ReturnValue != 0 {
		return pos, &ErrorCode{saveAttachResponse.ReturnValue}
	}
	return pos, nil
}

//Unmarshal function to produce RopOpenStreamResponse struct
func (openStreamResponse *RopOpenStreamResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0

	openStreamResponse.RopID, pos = utils.ReadByte(pos, resp)
	openStreamResponse.OutputHandleIndex, pos = utils.ReadByte(pos, resp)
	openStreamResponse.ReturnValue, pos = utils.ReadUint32(pos, resp)

	if openStreamResponse.ReturnValue != 0 {
		return pos, &ErrorCode{openStreamResponse.ReturnValue}
	}
	openStreamResponse.StreamSize, pos = utils.ReadUint32(pos, resp)
	return pos, nil
}

//Unmarshal function to produce RopOpenStreamResponse struct
func (setStreamSizeResponse *RopSetStreamSizeResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0

	setStreamSizeResponse.RopID, pos = utils.ReadByte(pos, resp)
	setStreamSizeResponse.OutputHandleIndex, pos = utils.ReadByte(pos, resp)
	setStreamSizeResponse.ReturnValue, pos = utils.ReadUint32(pos, resp)

	if setStreamSizeResponse.ReturnValue != 0 {
		return pos, &ErrorCode{setStreamSizeResponse.ReturnValue}
	}
	return pos, nil
}

//Unmarshal function to produce RopOpenStreamResponse struct
func (writeStreamResponse *RopWriteStreamResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0

	writeStreamResponse.RopID, pos = utils.ReadByte(pos, resp)
	writeStreamResponse.InputHandleIndex, pos = utils.ReadByte(pos, resp)
	writeStreamResponse.ReturnValue, pos = utils.ReadUint32(pos, resp)

	if writeStreamResponse.ReturnValue != 0 {
		return pos, &ErrorCode{writeStreamResponse.ReturnValue}
	}

	writeStreamResponse.WrittenSize, pos = utils.ReadUint16(pos, resp)
	return pos, nil
}

//Unmarshal function to produce RopCommitStreamResponse struct
func (commitStreamResponse *RopCommitStreamResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0

	commitStreamResponse.RopID, pos = utils.ReadByte(pos, resp)
	commitStreamResponse.InputHandleIndex, pos = utils.ReadByte(pos, resp)
	commitStreamResponse.ReturnValue, pos = utils.ReadUint32(pos, resp)

	if commitStreamResponse.ReturnValue != 0 {
		return pos, &ErrorCode{commitStreamResponse.ReturnValue}
	}

	return pos, nil
}

//Unmarshal func
func (ropGetHierarchyResponse *RopGetHierarchyTableResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0
	ropGetHierarchyResponse.RopID, pos = utils.ReadByte(pos, resp)
	ropGetHierarchyResponse.OutputHandle, pos = utils.ReadByte(pos, resp)
	ropGetHierarchyResponse.ReturnValue, pos = utils.ReadUint32(pos, resp)

	if ropGetHierarchyResponse.ReturnValue != 0x000000 {
		return pos, &ErrorCode{ropGetHierarchyResponse.ReturnValue}
	}

	ropGetHierarchyResponse.RowCount, pos = utils.ReadUint32(pos, resp)
	return pos, nil
}

//Unmarshal func
func (ropOpenMessageResponse *RopOpenMessageResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0
	ropOpenMessageResponse.RopID, pos = utils.ReadByte(pos, resp)
	ropOpenMessageResponse.OutputHandle, pos = utils.ReadByte(pos, resp)
	ropOpenMessageResponse.ReturnValue, pos = utils.ReadUint32(pos, resp)

	if ropOpenMessageResponse.ReturnValue != 0x000000 {
		return pos, &ErrorCode{ropOpenMessageResponse.ReturnValue}
	}

	ropOpenMessageResponse.HasNamedProperties, pos = utils.ReadByte(pos, resp)
	if ropOpenMessageResponse.HasNamedProperties == 1 {
		ropOpenMessageResponse.SubjectPrefix, pos = utils.ReadTypedString(pos, resp) //utils.ReadUnicodeString(pos, resp)
		ropOpenMessageResponse.NormalizedSubject, pos = utils.ReadTypedString(pos, resp)
		ropOpenMessageResponse.RecipientCount, pos = utils.ReadUint16(pos, resp)
		//utils.Read recipients
	}
	ropOpenMessageResponse.ColumnCount, pos = utils.ReadUint16(pos, resp)
	ropOpenMessageResponse.RowCount, pos = utils.ReadByte(pos, resp)

	return pos, nil
}

//Unmarshal func
func (ruleAction *RuleAction) Unmarshal(resp []byte) (int, error) {
	pos := 0
	ruleAction.Actions, pos = utils.ReadUint16(pos, resp)
	ruleAction.ActionLen, pos = utils.ReadUint16(pos, resp)
	ruleAction.ActionType, pos = utils.ReadByte(pos, resp)
	ruleAction.ActionFlavor, pos = utils.ReadUint32(pos, resp)
	ruleAction.ActionFlags, pos = utils.ReadUint32(pos, resp)
	ad := ActionData{}
	ad.Unmarshal(resp)
	return pos, nil
}

//Unmarshal func
func (actionData *ActionData) Unmarshal(resp []byte) (int, error) {
	pos := 0
	actionData.ActionElem, pos = utils.ReadBytes(pos, 4, resp)
	actionData.ActionName, pos = utils.ReadUTF16BE(pos, resp)
	actionData.Element, pos = utils.ReadBytes(pos, 1, resp)
	actionData.Trigger, pos = utils.ReadBytes(pos, 1, resp)
	actionData.Elem, pos = utils.ReadBytes(pos, 1, resp)
	actionData.EndPoint, pos = utils.ReadBytes(pos, 1, resp)
	actionData.Footer, pos = utils.ReadBytes(pos, 1, resp)
	return pos, nil
}

//Unmarshal func
func (ropGetPropertiesSpecificResponse *RopGetPropertiesSpecificResponse) Unmarshal(resp []byte, columns []PropertyTag) (int, error) {
	pos := 0
	ropGetPropertiesSpecificResponse.RopID, pos = utils.ReadByte(pos, resp)
	ropGetPropertiesSpecificResponse.InputHandleIndex, pos = utils.ReadByte(pos, resp)
	ropGetPropertiesSpecificResponse.ReturnValue, pos = utils.ReadUint32(pos, resp)

	if ropGetPropertiesSpecificResponse.ReturnValue != 0x000000 {
		return pos, &ErrorCode{ropGetPropertiesSpecificResponse.ReturnValue}
	}
	var rows []PropertyRow
	for _, property := range columns {
		trow := PropertyRow{}
		trow.Flag, pos = utils.ReadByte(pos, resp)
		if property.PropertyType == PtypInteger32 {
			trow.ValueArray, pos = utils.ReadBytes(pos, 2, resp)
			rows = append(rows, trow)
		} else if property.PropertyType == PtypString {
			trow.ValueArray, pos = utils.ReadUnicodeString(pos, resp)
			rows = append(rows, trow)
		} else if property.PropertyType == PtypBinary {
			cnt, p := utils.ReadByte(pos, resp)
			pos = p
			trow.ValueArray, pos = utils.ReadBytes(pos, int(cnt), resp)
			rows = append(rows, trow)
		}
	}
	ropGetPropertiesSpecificResponse.RowData = rows
	return pos, nil
}

//Unmarshal func
func (propTag *PropertyTag) Unmarshal(resp []byte) (int, error) {
	pos := 0
	propTag.PropertyType, pos = utils.ReadUint16(pos, resp)
	propTag.PropertyID, pos = utils.ReadUint16(pos, resp)
	return pos, nil
}
