package mapi

import (
	"errors"
	"fmt"

	"github.com/sensepost/ruler/utils"
)

// ErrorCode returns the mapi error code encountered
type ErrorCode struct {
	ErrorCode uint32
}

func (e *ErrorCode) Error() string {
	return fmt.Sprintf("mapi: non-zero return value. ERROR_CODE: %x - %s", e.ErrorCode, ErrorMapiCode{mapicode(e.ErrorCode)})
}

// TransportError returns the mapi error code encountered
type TransportError struct {
	ErrorValue error
}

func (e *TransportError) Error() string {
	return fmt.Sprintf("mapi: a transport layer error occurred. %s", e.ErrorValue)
}

var (
	//ErrTransport for when errors occurr on the transport layer
	ErrTransport = errors.New("mapi: a transport layer error occurred")
	//ErrMapiNonZero for non-zero return code in a MAPI request
	ErrMapiNonZero = errors.New("mapi: non-zero return value")
	//ErrUnknown hmm, we didn't account for this
	ErrUnknown = errors.New("mapi: an unhandled exception occurred")
	//ErrNotAdmin when attempting to get admin access to a mailbox
	ErrNotAdmin = errors.New("mapi: Invalid logon. Admin privileges requested but user is not admin")
	//ErrEmptyBuffer when we have returned a buffer that is too big for our RPC packet.. sometimes this happens..
	ErrEmptyBuffer = errors.New("An empty response buffer has been encountered. Likely that our response was too big for the current implementation of RPC/HTTP")
	//ErrNonZeroStatus when the execute response status is not zero - this is not the same as the individual ROP messages erroring out
	ErrNonZeroStatus = errors.New("The execute request returned a non-zero status code. Use --debug to see full response.")
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

// OpenFlags
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

// Property Data types
const (
	PtypInteger16         = 0x0002
	PtypInteger32         = 0x0003
	PtypInteger64         = 0x0014
	PtypFloating32        = 0x0004
	PtypFloating64        = 0x0005
	PtypBoolean           = 0x000B
	PtypString            = 0x001F
	PtypString8           = 0x001E
	PtypGUID              = 0x0048
	PtypRuleAction        = 0x00FE
	PtypRestriction       = 0x00FD
	PtypBinary            = 0x0102
	PtypMultipleBinary    = 0x1102
	PtypMultipleInteger32 = 0x1003
	PtypMultipleInteger64 = 0x1014
	PtypTime              = 0x0040
	PtypObject            = 0x000D
)

// Folder id/locations -- https://msdn.microsoft.com/en-us/library/office/cc815825.aspx
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

// Message status flags
const (
	MSRemoteDownload = 0x00001000
	MSInConflict     = 0x00000800
	MSRemoteDelete   = 0x00002000
)

type mapicode uint32

func (e mapicode) String() string {
	switch e {
	case MAPI_E_INTERFACE_NOT_SUPPORTED:
		return "MAPI_E_INTERFACE_NOT_SUPPORTED"
	case MAPI_E_CALL_FAILED:
		return "MAPI_E_CALL_FAILED"
	case MAPI_E_NOT_IMPLEMENTED:
		return "MAPI_E_NOT_IMPLEMENTED"
	case MAPI_E_NO_ACCESS:
		return "MAPI_E_NO_ACCESS"
	case MAPI_E_NOT_ENOUGH_MEMORY:
		return "MAPI_E_NOT_ENOUGH_MEMORY"
	case MAPI_E_INVALID_PARAMETER:
		return "MAPI_E_INVALID_PARAMETER"
	case MAPI_E_NO_SUPPORT:
		return "MAPI_E_NO_SUPPORT"
	case MAPI_E_BAD_CHARWIDTH:
		return "MAPI_E_BAD_CHARWIDTH"
	case MAPI_E_STRING_TOO_LONG:
		return "MAPI_E_STRING_TOO_LONG"
	case MAPI_E_UNKNOWN_FLAGS:
		return "MAPI_E_UNKNOWN_FLAGS"
	case MAPI_E_INVALID_ENTRYID:
		return "MAPI_E_INVALID_ENTRYID"
	case MAPI_E_INVALID_OBJECT:
		return "MAPI_E_INVALID_OBJECT"
	case MAPI_E_OBJECT_CHANGED:
		return "MAPI_E_OBJECT_CHANGED"
	case MAPI_E_OBJECT_DELETED:
		return "MAPI_E_OBJECT_DELETED"
	case MAPI_E_BUSY:
		return "MAPI_E_BUSY"
	case MAPI_E_NOT_ENOUGH_DISK:
		return "MAPI_E_NOT_ENOUGH_DISK"
	case MAPI_E_NOT_ENOUGH_RESOURCES:
		return "MAPI_E_NOT_ENOUGH_RESOURCES"
	case MAPI_E_NOT_FOUND:
		return "MAPI_E_NOT_FOUND"
	case MAPI_E_VERSION:
		return "MAPI_E_VERSION"
	case MAPI_E_LOGON_FAILED:
		return "MAPI_E_LOGON_FAILED"
	case MAPI_E_SESSION_LIMIT:
		return "MAPI_E_SESSION_LIMIT"
	case MAPI_E_USER_CANCEL:
		return "MAPI_E_USER_CANCEL"
	case MAPI_E_UNABLE_TO_ABORT:
		return "MAPI_E_UNABLE_TO_ABORT"
	case MAPI_E_NETWORK_ERROR:
		return "MAPI_E_NETWORK_ERROR"
	case MAPI_E_DISK_ERROR:
		return "MAPI_E_DISK_ERROR"
	case MAPI_E_TOO_COMPLEX:
		return "MAPI_E_TOO_COMPLEX"
	case MAPI_E_BAD_COLUMN:
		return "MAPI_E_BAD_COLUMN"
	case MAPI_E_EXTENDED_ERROR:
		return "MAPI_E_EXTENDED_ERROR"
	case MAPI_E_COMPUTED:
		return "MAPI_E_COMPUTED"
	case MAPI_E_CORRUPT_DATA:
		return "MAPI_E_CORRUPT_DATA"
	case MAPI_E_UNCONFIGURED:
		return "MAPI_E_UNCONFIGURED"
	case MAPI_E_FAILONEPROVIDER:
		return "MAPI_E_FAILONEPROVIDER"
	case MAPI_E_UNKNOWN_CPID:
		return "MAPI_E_UNKNOWN_CPID"
	case MAPI_E_UNKNOWN_LCID:
		return "MAPI_E_UNKNOWN_LCID"
	case MAPI_E_PASSWORD_CHANGE_REQUIRED:
		return "MAPI_E_PASSWORD_CHANGE_REQUIRED"
	case MAPI_E_PASSWORD_EXPIRED:
		return "MAPI_E_PASSWORD_EXPIRED"
	case MAPI_E_INVALID_WORKSTATION_ACCOUNT:
		return "MAPI_E_INVALID_WORKSTATION_ACCOUNT"
	case MAPI_E_INVALID_ACCESS_TIME:
		return "MAPI_E_INVALID_ACCESS_TIME"
	case MAPI_E_ACCOUNT_DISABLED:
		return "MAPI_E_ACCOUNT_DISABLED"
	case MAPI_E_END_OF_SESSION:
		return "MAPI_E_END_OF_SESSION"
	case MAPI_E_UNKNOWN_ENTRYID:
		return "MAPI_E_UNKNOWN_ENTRYID"
	case MAPI_E_MISSING_REQUIRED_COLUMN:
		return "MAPI_E_MISSING_REQUIRED_COLUMN"
	case MAPI_W_NO_SERVICE:
		return "MAPI_W_NO_SERVICE"
	case MAPI_E_BAD_VALUE:
		return "MAPI_E_BAD_VALUE"
	case MAPI_E_INVALID_TYPE:
		return "MAPI_E_INVALID_TYPE"
	case MAPI_E_TYPE_NO_SUPPORT:
		return "MAPI_E_TYPE_NO_SUPPORT"
	case MAPI_E_UNEXPECTED_TYPE:
		return "MAPI_E_UNEXPECTED_TYPE"
	case MAPI_E_TOO_BIG:
		return "MAPI_E_TOO_BIG"
	case MAPI_E_DECLINE_COPY:
		return "MAPI_E_DECLINE_COPY"
	case MAPI_E_UNEXPECTED_ID:
		return "MAPI_E_UNEXPECTED_ID"
	case MAPI_W_ERRORS_RETURNED:
		return "MAPI_W_ERRORS_RETURNED"
	case MAPI_E_UNABLE_TO_COMPLETE:
		return "MAPI_E_UNABLE_TO_COMPLETE"
	case MAPI_E_TIMEOUT:
		return "MAPI_E_TIMEOUT"
	case MAPI_E_TABLE_EMPTY:
		return "MAPI_E_TABLE_EMPTY"
	case MAPI_E_TABLE_TOO_BIG:
		return "MAPI_E_TABLE_TOO_BIG"
	case MAPI_E_INVALID_BOOKMARK:
		return "MAPI_E_INVALID_BOOKMARK"
	case MAPI_W_POSITION_CHANGED:
		return "MAPI_W_POSITION_CHANGED"
	case MAPI_W_APPROX_COUNT:
		return "MAPI_W_APPROX_COUNT"
	case MAPI_E_WAIT:
		return "MAPI_E_WAIT"
	case MAPI_E_CANCEL:
		return "MAPI_E_CANCEL"
	case MAPI_E_NOT_ME:
		return "MAPI_E_NOT_ME"
	case MAPI_W_CANCEL_MESSAGE:
		return "MAPI_W_CANCEL_MESSAGE"
	case MAPI_E_CORRUPT_STORE:
		return "MAPI_E_CORRUPT_STORE"
	case MAPI_E_NOT_IN_QUEUE:
		return "MAPI_E_NOT_IN_QUEUE"
	case MAPI_E_NO_SUPPRESS:
		return "MAPI_E_NO_SUPPRESS"
	case MAPI_E_COLLISION:
		return "MAPI_E_COLLISION"
	case MAPI_E_NOT_INITIALIZED:
		return "MAPI_E_NOT_INITIALIZED"
	case MAPI_E_NON_STANDARD:
		return "MAPI_E_NON_STANDARD"
	case MAPI_E_NO_RECIPIENTS:
		return "MAPI_E_NO_RECIPIENTS"
	case MAPI_E_SUBMITTED:
		return "MAPI_E_SUBMITTED"
	case MAPI_E_HAS_FOLDERS:
		return "MAPI_E_HAS_FOLDERS"
	case MAPI_E_HAS_MESSAGES:
		return "MAPI_E_HAS_MESSAGES"
	case MAPI_E_FOLDER_CYCLE:
		return "MAPI_E_FOLDER_CYCLE"
	case MAPI_E_STORE_FULL:
		return "MAPI_E_STORE_FULL"
	case MAPI_E_LOCKID_LIMIT:
		return "MAPI_E_LOCKID_LIMIT"
	case MAPI_W_PARTIAL_COMPLETION:
		return "MAPI_W_PARTIAL_COMPLETION"
	case MAPI_E_AMBIGUOUS_RECIP:
		return "MAPI_E_AMBIGUOUS_RECIP"
	case SYNC_E_OBJECT_DELETED:
		return "SYNC_E_OBJECT_DELETED"
	case SYNC_E_IGNORE:
		return "SYNC_E_IGNORE"
	case SYNC_E_CONFLICT:
		return "SYNC_E_CONFLICT"
	case SYNC_E_NO_PARENT:
		return "SYNC_E_NO_PARENT"
	case SYNC_E_INCEST:
		return "SYNC_E_INCEST"
	case SYNC_E_UNSYNCHRONIZED:
		return "SYNC_E_UNSYNCHRONIZED"
	case SYNC_W_PROGRESS:
		return "SYNC_W_PROGRESS"
	case SYNC_W_CLIENT_CHANGE_NEWER:
		return "SYNC_W_CLIENT_CHANGE_NEWER"

	}
	return "CODE_NOT_FOUND"
}

// ErrorMapiCode provides a mapping of uint32 error code to string
type ErrorMapiCode struct {
	X mapicode
}

const (
	MAPI_E_NOT_IMPLEMENTED             mapicode = 0x80040FFF
	MAPI_E_INTERFACE_NOT_SUPPORTED     mapicode = 0x80004002
	MAPI_E_CALL_FAILED                 mapicode = 0x80004005
	MAPI_E_NO_ACCESS                   mapicode = 0x80070005
	MAPI_E_NOT_ENOUGH_MEMORY           mapicode = 0x8007000e
	MAPI_E_INVALID_PARAMETER           mapicode = 0x80070057
	MAPI_E_NO_SUPPORT                  mapicode = 0x80040102
	MAPI_E_BAD_CHARWIDTH               mapicode = 0x80040103
	MAPI_E_STRING_TOO_LONG             mapicode = 0x80040105
	MAPI_E_UNKNOWN_FLAGS               mapicode = 0x80040106
	MAPI_E_INVALID_ENTRYID             mapicode = 0x80040107
	MAPI_E_INVALID_OBJECT              mapicode = 0x80040108
	MAPI_E_OBJECT_CHANGED              mapicode = 0x80040109
	MAPI_E_OBJECT_DELETED              mapicode = 0x8004010a
	MAPI_E_BUSY                        mapicode = 0x8004010b
	MAPI_E_NOT_ENOUGH_DISK             mapicode = 0x8004010d
	MAPI_E_NOT_ENOUGH_RESOURCES        mapicode = 0x8004010e
	MAPI_E_NOT_FOUND                   mapicode = 0x8004010f
	MAPI_E_VERSION                     mapicode = 0x80040110
	MAPI_E_LOGON_FAILED                mapicode = 0x80040111
	MAPI_E_SESSION_LIMIT               mapicode = 0x80040112
	MAPI_E_USER_CANCEL                 mapicode = 0x80040113
	MAPI_E_UNABLE_TO_ABORT             mapicode = 0x80040114
	MAPI_E_NETWORK_ERROR               mapicode = 0x80040115
	MAPI_E_DISK_ERROR                  mapicode = 0x80040116
	MAPI_E_TOO_COMPLEX                 mapicode = 0x80040117
	MAPI_E_BAD_COLUMN                  mapicode = 0x80040118
	MAPI_E_EXTENDED_ERROR              mapicode = 0x80040119
	MAPI_E_COMPUTED                    mapicode = 0x8004011a
	MAPI_E_CORRUPT_DATA                mapicode = 0x8004011b
	MAPI_E_UNCONFIGURED                mapicode = 0x8004011c
	MAPI_E_FAILONEPROVIDER             mapicode = 0x8004011d
	MAPI_E_UNKNOWN_CPID                mapicode = 0x8004011e
	MAPI_E_UNKNOWN_LCID                mapicode = 0x8004011f
	MAPI_E_PASSWORD_CHANGE_REQUIRED    mapicode = 0x80040120
	MAPI_E_PASSWORD_EXPIRED            mapicode = 0x80040121
	MAPI_E_INVALID_WORKSTATION_ACCOUNT mapicode = 0x80040122
	MAPI_E_INVALID_ACCESS_TIME         mapicode = 0x80040123
	MAPI_E_ACCOUNT_DISABLED            mapicode = 0x80040124
	MAPI_E_END_OF_SESSION              mapicode = 0x80040200
	MAPI_E_UNKNOWN_ENTRYID             mapicode = 0x80040201
	MAPI_E_MISSING_REQUIRED_COLUMN     mapicode = 0x80040202
	MAPI_W_NO_SERVICE                  mapicode = 0x00040203
	MAPI_E_BAD_VALUE                   mapicode = 0x80040301
	MAPI_E_INVALID_TYPE                mapicode = 0x80040302
	MAPI_E_TYPE_NO_SUPPORT             mapicode = 0x80040303
	MAPI_E_UNEXPECTED_TYPE             mapicode = 0x80040304
	MAPI_E_TOO_BIG                     mapicode = 0x80040305
	MAPI_E_DECLINE_COPY                mapicode = 0x80040306
	MAPI_E_UNEXPECTED_ID               mapicode = 0x80040307
	MAPI_W_ERRORS_RETURNED             mapicode = 0x00040380
	MAPI_E_UNABLE_TO_COMPLETE          mapicode = 0x80040400
	MAPI_E_TIMEOUT                     mapicode = 0x80040401
	MAPI_E_TABLE_EMPTY                 mapicode = 0x80040402
	MAPI_E_TABLE_TOO_BIG               mapicode = 0x80040403
	MAPI_E_INVALID_BOOKMARK            mapicode = 0x80040405
	MAPI_W_POSITION_CHANGED            mapicode = 0x00040481
	MAPI_W_APPROX_COUNT                mapicode = 0x00040482
	MAPI_E_WAIT                        mapicode = 0x80040500
	MAPI_E_CANCEL                      mapicode = 0x80040501
	MAPI_E_NOT_ME                      mapicode = 0x80040502
	MAPI_W_CANCEL_MESSAGE              mapicode = 0x00040580
	MAPI_E_CORRUPT_STORE               mapicode = 0x80040600
	MAPI_E_NOT_IN_QUEUE                mapicode = 0x80040601
	MAPI_E_NO_SUPPRESS                 mapicode = 0x80040602
	MAPI_E_COLLISION                   mapicode = 0x80040604
	MAPI_E_NOT_INITIALIZED             mapicode = 0x80040605
	MAPI_E_NON_STANDARD                mapicode = 0x80040606
	MAPI_E_NO_RECIPIENTS               mapicode = 0x80040607
	MAPI_E_SUBMITTED                   mapicode = 0x80040608
	MAPI_E_HAS_FOLDERS                 mapicode = 0x80040609
	MAPI_E_HAS_MESSAGES                mapicode = 0x8004060a
	MAPI_E_FOLDER_CYCLE                mapicode = 0x8004060b
	MAPI_E_STORE_FULL                  mapicode = 0x8004060c
	MAPI_E_LOCKID_LIMIT                mapicode = 0x8004060D
	MAPI_W_PARTIAL_COMPLETION          mapicode = 0x00040680
	MAPI_E_AMBIGUOUS_RECIP             mapicode = 0x80040700
	SYNC_E_OBJECT_DELETED              mapicode = 0x80040800
	SYNC_E_IGNORE                      mapicode = 0x80040801
	SYNC_E_CONFLICT                    mapicode = 0x80040802
	SYNC_E_NO_PARENT                   mapicode = 0x80040803
	SYNC_E_INCEST                      mapicode = 0x80040804
	SYNC_E_UNSYNCHRONIZED              mapicode = 0x80040805
	SYNC_W_PROGRESS                    mapicode = 0x00040820
	SYNC_W_CLIENT_CHANGE_NEWER         mapicode = 0x00040821
)

//-------- TAGS -------

//Find these in [MS-OXPROPS]

// PidTagRuleID the TaggedPropertyValue for rule id
var PidTagRuleID = PropertyTag{PtypInteger64, 0x6674}

// PidTagRuleName the TaggedPropertyValue for rule id
var PidTagRuleName = PropertyTag{PtypString, 0x6682}

// PidTagRuleSequence the TaggedPropertyValue for rule id
var PidTagRuleSequence = PropertyTag{PtypInteger32, 0x6676}

// PidTagRuleState the TaggedPropertyValue for rule id
var PidTagRuleState = PropertyTag{PtypInteger32, 0x6677}

// PidTagRuleCondition the TaggedPropertyValue for rule id
var PidTagRuleCondition = PropertyTag{PtypRestriction, 0x6679}

// PidTagRuleActions the TaggedPropertyValue for rule id
var PidTagRuleActions = PropertyTag{PtypRuleAction, 0x6680}

// PidTagRuleProvider the TaggedPropertyValue for rule id
var PidTagRuleProvider = PropertyTag{PtypString, 0x6681}

// PidTagRuleProviderData the TaggedPropertyValue for rule id
var PidTagRuleProviderData = PropertyTag{PtypBinary, 0x6684}

// PidTagRuleLevel the TaggedPropertyValue for rule level
var PidTagRuleLevel = PropertyTag{PtypInteger32, 0x6683}

// PidTagRuleUserFlags the TaggedPropertyValue for rule user flags
var PidTagRuleUserFlags = PropertyTag{PtypInteger32, 0x6678}

// PidTagParentFolderID Contains a value that contains the Folder ID
var PidTagParentFolderID = PropertyTag{PtypInteger64, 0x6749}

// PidTagAccess indicates operations available
var PidTagAccess = PropertyTag{PtypInteger32, 0x0ff4}

// PidTagMemberName contains user-readable name of the user
var PidTagMemberName = PropertyTag{PtypBinary, 0x6672}

// PidTagDefaultPostMessageClass contains message class of the object
var PidTagDefaultPostMessageClass = PropertyTag{PtypString, 0x36e5}

// PidTagDisplayName display name of the folder
var PidTagDisplayName = PropertyTag{PtypString, 0x3001}

// PidTagEntryID display name of the folder
var PidTagEntryID = PropertyTag{PtypBinary, 0x0FFF}

// PidTagEmailAddress display name of the folder
var PidTagEmailAddress = PropertyTag{PtypString, 0x3003}

// PidTagAddressType display name of the folder
var PidTagAddressType = PropertyTag{PtypString, 0x3001}

// PidTagFolderType specifies the type of folder that includes the root folder,
var PidTagFolderType = PropertyTag{PtypInteger32, 0x3601}

// PidTagFolderID the ID of the folder
var PidTagFolderID = PropertyTag{PtypInteger64, 0x6748}

// PidTagContentCount specifies the number of rows under the header row
var PidTagContentCount = PropertyTag{PtypInteger32, 0x3602}

// PidTagContentUnreadCount specifies the number of rows under the header row
var PidTagContentUnreadCount = PropertyTag{PtypInteger32, 0x3603}

// PidTagSubfolders specifies whether the folder has subfolders
var PidTagSubfolders = PropertyTag{PtypBoolean, 0x360a}

// PidTagLocaleID contains the Logon object LocaleID
var PidTagLocaleID = PropertyTag{PtypInteger32, 0x66A1}

//----Tags for email properties ----

// PidTagSentMailSvrEID id of the sent folder
var PidTagSentMailSvrEID = PropertyTag{0x00FB, 0x6740}

// PidTagBody a
var PidTagBody = PropertyTag{PtypString, 0x1000}

// PidTagBodyContentID a
var PidTagBodyContentID = PropertyTag{PtypString, 0x1015}

// PidTagConversationTopic a
var PidTagConversationTopic = PropertyTag{PtypString, 0x0070}

// PidTagMessageClass this will always be IPM.Note
var PidTagMessageClass = PropertyTag{PtypString, 0x001A}

// PidTagMessageClassIPMNote this will always be IPM.Note
var PidTagMessageClassIPMNote = TaggedPropertyValue{PropertyTag{PtypString, 0x001A}, utils.UniString("IPM.Note")}

// PidTagMessageFlags setting this to unsent
var PidTagMessageFlags = PropertyTag{PtypInteger32, 0x0E07} //0x00000008

// PidTagIconIndexOld index of the icon to display
var PidTagIconIndexOld = TaggedPropertyValue{PropertyTag{PtypInteger32, 0x1080}, []byte{0xFF, 0xFF, 0xFF, 0xFF}}

// PidTagMessageEditorFormatOld format lets do plaintext
var PidTagMessageEditorFormatOld = TaggedPropertyValue{PropertyTag{PtypInteger32, 0x5909}, []byte{0x01, 0x00, 0x00, 0x00}}

// PidTagNativeBody format of the body
var PidTagNativeBody = PropertyTag{PtypInteger32, 0x1016}

// PidTagMessageLocaleID format lets do en-us
var PidTagMessageLocaleID = TaggedPropertyValue{PropertyTag{PtypInteger32, 0x3FF1}, []byte{0x09, 0x04, 0x00, 0x00}}

// PidTagPrimarySendAccount who is sending
var PidTagPrimarySendAccount = PropertyTag{PtypString, 0x0E28}

// PidTagObjectType used in recepient
var PidTagObjectType = PropertyTag{PtypInteger32, 0x0FFE}

// PidTagImportance used in recepient
var PidTagImportance = PropertyTag{PtypInteger32, 0x0017}

// PidTagDisplayType  used in recepient
var PidTagDisplayType = PropertyTag{PtypInteger32, 0x3900}

// PidTagAddressBookDisplayNamePrintable  used in recepient
var PidTagAddressBookDisplayNamePrintable = PropertyTag{PtypString, 0x39FF}

// PidTagSMTPAddress used in recepient
var PidTagSMTPAddress = PropertyTag{PtypString, 0x39FE}

// PidTagSendInternetEncoding  used in recepient
var PidTagSendInternetEncoding = PropertyTag{PtypInteger32, 0x3a71}

// PidTagDisplayTypeEx used in recepient
var PidTagDisplayTypeEx = PropertyTag{PtypInteger32, 0x3905}

// PidTagRecipientDisplayName  used in recepient
var PidTagRecipientDisplayName = PropertyTag{PtypString, 0x5FF6}

// PidTagRecipientFlags used in recepient
var PidTagRecipientFlags = PropertyTag{PtypInteger32, 0x5FFD}

// PidTagRecipientTrackStatus used in recepient
var PidTagRecipientTrackStatus = PropertyTag{PtypInteger32, 0x5FFF}

// Unspecifiedproperty  used in recepient
var Unspecifiedproperty = PropertyTag{PtypInteger32, 0x5FDE}

// PidTagRecipientOrder used in recepient
var PidTagRecipientOrder = PropertyTag{PtypInteger32, 0x5FDF}

// PidTagRecipientEntryID  used in recepient
var PidTagRecipientEntryID = PropertyTag{PtypBinary, 0x5FF7}

// PidTagSubjectPrefix used in recepient
var PidTagSubjectPrefix = PropertyTag{PtypString, 0x0003}

// PidTagNormalizedSubject used in recepient
var PidTagNormalizedSubject = PropertyTag{PtypString, 0x0E1D}

// PidTagSubject used in recepient
var PidTagSubject = PropertyTag{PtypString, 0x0037}

// PidTagHidden specify whether folder is hidden
var PidTagHidden = PropertyTag{PtypBoolean, 0x10F4}

// PidTagInstID identifier for all instances of a row in the table
var PidTagInstID = PropertyTag{PtypInteger64, 0x674D}

// PidTagInstanceNum identifier for single instance of a row in the table
var PidTagInstanceNum = PropertyTag{PtypInteger32, 0x674E}

// PidTagMid is the message id of a message in a store
var PidTagMid = PropertyTag{PtypInteger64, 0x674A}

// PidTagBodyHTML is the message id of a message in a store
var PidTagBodyHTML = PropertyTag{PtypBinary, 0x1013}

// PidTagHTMLBody is the same as above?
var PidTagHTMLBody = PropertyTag{PtypString, 0x1013}

var PidTagAttachMethod = PropertyTag{PtypInteger32, 0x3705}

var PidTagRenderingPosition = PropertyTag{PtypInteger32, 0x370B}

var PidTagAttachContentId = PropertyTag{PtypString, 0x03712}

var PidTagAttachMimeTag = PropertyTag{PtypString, 0x370E}

var PidTagAttachmentLinkId = PropertyTag{PtypInteger32, 0x7FFA}

var PidTagAttachFlags = PropertyTag{PtypInteger32, 0x3714}

var PidTagAttachmentHidden = PropertyTag{PtypBoolean, 0x7FFE}

var PidTagAttachLongFilename = PropertyTag{PtypString, 0x3707}

var PidTagAttachFilename = PropertyTag{PtypString, 0x3704}

var PidTagAttachExtension = PropertyTag{PtypString, 0x3703}

var PidTagMessageAttachments = PropertyTag{PtypObject, 0x0E13}

var PidTagAttachPathName = PropertyTag{PtypString, 0x3708}
var PidTagAttachLongPathName = PropertyTag{PtypString, 0x370D}
var PidTagAttachPayloadProviderGuidString = PropertyTag{PtypString, 0x3719}
var PidTagTrustSender = PropertyTag{PtypInteger32, 0x0E79}
var PidTagAttachDataBinary = PropertyTag{PtypBinary, 0x3701}

var PidTagIconIndex = PropertyTag{PtypInteger32, 0x1080}
var PidTagMessageEditorFormat = PropertyTag{PtypInteger32, 0x5909}
var PidTagSenderEmailAddress = PropertyTag{PtypString, 0x0C1F}
var PidTagDeleteAfterSubmit = PropertyTag{PtypBoolean, 0x0E01}
var PidTagOfflineAddressBookName = PropertyTag{PtypString, 0x6800}
var PidTagOfflineAddressBookTruncatedProps = PropertyTag{PtypMultipleInteger32, 0x6805}
var PidTagOfflineAddressBookLangID = PropertyTag{PtypInteger32, 0x6807}
var PidTagOfflineAddressBookFileType = PropertyTag{PtypBoolean, 0x6808}
var PidTagSendOutlookRecallReport = PropertyTag{PtypBoolean, 0x6803}
var PidTagOABCompressedSize = PropertyTag{PtypGUID, 0x6809}
var PidTagOABDN = PropertyTag{PtypGUID, 0x6804}

var PidTag6830 = PropertyTag{PtypString8, 0x6830}
var PidTag682C = PropertyTag{PtypMultipleInteger64, 0x682C}
var PidTag6831 = PropertyTag{PtypBinary, 0x6831}
var PidTag6832 = PropertyTag{PtypBinary, 0x6832}
var PidTag6823 = PropertyTag{PtypBinary, 0x6823}
var PidTag6824 = PropertyTag{PtypBinary, 0x6824}
var PidTag6827 = PropertyTag{PtypString8, 0x6827}
var PidTag6B00 = PropertyTag{PtypString8, 0x6B00}
var PidTag6902 = PropertyTag{0x001E, 0x6902}
var PidTag6900 = PropertyTag{0x0003, 0x6900}
var PidTagComment = PropertyTag{PtypString, 0x3004}

var PidTagSenderEntryId = PropertyTag{PtypBinary, 0x0C19}
var PidTagFolderWebViewInfo = PropertyTag{PtypBinary, 0x36DF}
var PidTagPurportedSenderDomain = PropertyTag{PtypString, 0x4083}
var PidTagBodyContentLocation = PropertyTag{PtypString, 0x1014}

var PidTagClientInfo = PropertyTag{PtypString, 0x80C7}

var PidTagVoiceMessageAttachmentOrder = PropertyTag{PtypString, 0x6805}
var PidTagVoiceMessageDuration = PropertyTag{PtypInteger32, 0x6801}
var PidTagVoiceMessageSenderName = PropertyTag{PtypString, 0x6803}

var PidTagRoamingDatatypes = PropertyTag{PtypInteger32, 0x7C06}
var PidTagRoamingDictionary = PropertyTag{PtypBinary, 0x7C07}
var PidTagRoamingXmlStream = PropertyTag{PtypBinary, 0x7C08}

var PidTagSearchAllIndexedProps = PropertyTag{PtypString, 0x0EAF}
