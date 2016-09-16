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

//PidTagFolderType specifies the type of folder that includes the root folder,
var PidTagFolderType = PropertyTag{PtypInteger32, 0x3601}

//PidTagContentCount specifies the number of rows under the header row
var PidTagContentCount = PropertyTag{PtypInteger32, 0x3602}

//PidTagContentUnreadCount specifies the number of rows under the header row
var PidTagContentUnreadCount = PropertyTag{PtypInteger32, 0x3603}

//PidTagSubfolders specifies whether the folder has subfolders
var PidTagSubfolders = PropertyTag{PtypBoolean, 0x360a}

//PidTagLocaleID contains the Logon object LocaleID
var PidTagLocaleID = PropertyTag{PtypInteger32, 0x66A1}
