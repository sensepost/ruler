package mapi

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
	PtypTime           = 0x0040
)

//Folder id/locations -- https://msdn.microsoft.com/en-us/library/office/cc815825.aspx
// ^ this seems to lie
const (
	TOP            = 0 //Contains outgoing IPM messages.
	DEFFEREDACTION = 1 //Contains IPM messages that are marked for deletion.
	SPOOLERQ       = 2 //Contains IPM messages that have been sent.
	IPM            = 3 //IPM root folder Contains folders for managing IPM messages.
	INBOX          = 4 //Receive folder Contains incoming messages for a particular message class.
	OUTBOX         = 5 //Search-results root folder Contains folders for managing search results.
	SENT           = 6 //Common-views root folder Contains folders for managing views for the message store.
	DELETED        = 7 //Personal-views root folder
	COMMON         = 8
	SCHEDULE       = 9
	FINDER         = 10
	VIEWS          = 11
	SHORTCUTS      = 12
)

//Message status flags
const (
	MSRemoteDownload = 0x00001000
	MSInConflict     = 0x00000800
	MSRemoteDelete   = 0x00002000
)

//-------- TAGS -------

//Find these in [MS-OXPROPS]

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

//PidTagParentFolderID Contains a value that contains the Folder ID
var PidTagParentFolderID = PropertyTag{PtypInteger64, 0x6749}

//PidTagAccess indicates operations available
var PidTagAccess = PropertyTag{PtypInteger32, 0x0ff4}

//PidTagMemberName contains user-readable name of the user
var PidTagMemberName = PropertyTag{PtypBinary, 0x6672}

//PidTagDefaultPostMessageClass contains message class of the object
var PidTagDefaultPostMessageClass = PropertyTag{PtypString, 0x36e5}

//PidTagDisplayName display name of the folder
var PidTagDisplayName = PropertyTag{PtypString, 0x3001}

//PidTagEntryID display name of the folder
var PidTagEntryID = PropertyTag{PtypBinary, 0x0FFF}

//PidTagEmailAddress display name of the folder
var PidTagEmailAddress = PropertyTag{PtypString, 0x3003}

//PidTagAddressType display name of the folder
var PidTagAddressType = PropertyTag{PtypString, 0x3001}

//PidTagFolderType specifies the type of folder that includes the root folder,
var PidTagFolderType = PropertyTag{PtypInteger32, 0x3601}

//PidTagFolderID the ID of the folder
var PidTagFolderID = PropertyTag{PtypInteger64, 0x6748}

//PidTagContentCount specifies the number of rows under the header row
var PidTagContentCount = PropertyTag{PtypInteger32, 0x3602}

//PidTagContentUnreadCount specifies the number of rows under the header row
var PidTagContentUnreadCount = PropertyTag{PtypInteger32, 0x3603}

//PidTagSubfolders specifies whether the folder has subfolders
var PidTagSubfolders = PropertyTag{PtypBoolean, 0x360a}

//PidTagLocaleID contains the Logon object LocaleID
var PidTagLocaleID = PropertyTag{PtypInteger32, 0x66A1}

//----Tags for email properties ----

//PidTagSentMailSvrEID id of the sent folder
var PidTagSentMailSvrEID = PropertyTag{0x00FB, 0x6740}

//PidTagBody a
var PidTagBody = PropertyTag{PtypString, 0x1000}

//PidTagBodyContentId a
var PidTagBodyContentID = PropertyTag{PtypString, 0x1015}

//PidTagConversationTopic a
var PidTagConversationTopic = PropertyTag{PtypString, 0x0070}

//PidTagMessageClass this will always be IPM.Note
var PidTagMessageClass = PropertyTag{PtypString, 0x001A}

//PidTagMessageClass this will always be IPM.Note
var PidTagMessageClassIPMNote = TaggedPropertyValue{PropertyTag{PtypString, 0x001A}, UniString("IPM.Note")}

//PidTagMessageFlags setting this to unsent
var PidTagMessageFlags = PropertyTag{PtypInteger32, 0x0E07} //0x00000008

//PidTagIconIndex index of the icon to display
var PidTagIconIndex = TaggedPropertyValue{PropertyTag{PtypInteger32, 0x1080}, []byte{0xFF, 0xFF, 0xFF, 0xFF}}

//PidTagMessageEditorFormat format lets do plaintext
var PidTagMessageEditorFormat = TaggedPropertyValue{PropertyTag{PtypInteger32, 0x5909}, []byte{0x01, 0x00, 0x00, 0x00}}

//PidTagNativeBody format of the body
var PidTagNativeBody = PropertyTag{PtypInteger32, 0x1016}

//PidTagMessageLocaleID format lets do en-us
var PidTagMessageLocaleID = TaggedPropertyValue{PropertyTag{PtypInteger32, 0x3FF1}, []byte{0x09, 0x04, 0x00, 0x00}}

//PidTagPrimarySendAccount who is sending
var PidTagPrimarySendAccount = PropertyTag{PtypString, 0x0E28}

//PidTagObjectType used in recepient
var PidTagObjectType = PropertyTag{PtypInteger32, 0x0FFE}

//PidTagDisplayType  used in recepient
var PidTagDisplayType = PropertyTag{PtypInteger32, 0x3900}

//PidTagAddressBookDisplayNamePrintable  used in recepient
var PidTagAddressBookDisplayNamePrintable = PropertyTag{PtypString, 0x39FF}

//PidTagSMTPAddress used in recepient
var PidTagSMTPAddress = PropertyTag{PtypString, 0x39FE}

//PidTagSendInternetEncoding  used in recepient
var PidTagSendInternetEncoding = PropertyTag{PtypInteger32, 0x3a71}

//PidTagDisplayTypeEx used in recepient
var PidTagDisplayTypeEx = PropertyTag{PtypInteger32, 0x3905}

//PidTagRecipientDisplayName  used in recepient
var PidTagRecipientDisplayName = PropertyTag{PtypString, 0x5FF6}

//PidTagRecipientFlags used in recepient
var PidTagRecipientFlags = PropertyTag{PtypInteger32, 0x5FFD}

//PidTagRecipientTrackStatus used in recepient
var PidTagRecipientTrackStatus = PropertyTag{PtypInteger32, 0x5FFF}

//Unspecifiedproperty  used in recepient
var Unspecifiedproperty = PropertyTag{PtypInteger32, 0x5FDE}

//PidTagRecipientOrder used in recepient
var PidTagRecipientOrder = PropertyTag{PtypInteger32, 0x5FDF}

//PidTagRecipientEntryID  used in recepient
var PidTagRecipientEntryID = PropertyTag{PtypBinary, 0x5FF7}

//PidTagSubjectPrefix used in recepient
var PidTagSubjectPrefix = PropertyTag{PtypString, 0x0003}

//PidTagNormalizedSubject used in recepient
var PidTagNormalizedSubject = PropertyTag{PtypString, 0x0E1D}

//PidTagSubject used in recepient
var PidTagSubject = PropertyTag{PtypString, 0x0037}

//PidTagHidden specify whether folder is hidden
var PidTagHidden = PropertyTag{PtypBoolean, 0x10F4}

//PidTagInstID identifier for all instances of a row in the table
var PidTagInstID = PropertyTag{PtypInteger64, 0x674D}

//PidTagInstanceNum identifier for single instance of a row in the table
var PidTagInstanceNum = PropertyTag{PtypInteger32, 0x674E}

//PidTagMid is the message id of a message in a store
var PidTagMid = PropertyTag{PtypInteger64, 0x674A}

//PidTagBodyHtml is the message id of a message in a store
var PidTagBodyHtml = PropertyTag{PtypBinary, 0x1013}

var PidTagHtmlBody = PropertyTag{PtypString, 0x1013}
