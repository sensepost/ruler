package mapi

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"time"

	httpntlm "github.com/sensepost/ruler/http-ntlm"
	rpchttp "github.com/sensepost/ruler/rpc-http"
	"github.com/sensepost/ruler/utils"
)

// HTTP transport type for MAPI over HTTP types
const HTTP int = 1

// RPC over HTTP transport type for traditional MAPI
const RPC int = 2

var cnt = 0
var client http.Client

// AuthSession holds all our session related info
var AuthSession *utils.Session

// ExtractMapiURL extract the External mapi url from the autodiscover response
func ExtractMapiURL(resp *utils.AutodiscoverResp) string {
	for _, v := range resp.Response.Account.Protocol {
		if v.TypeAttr == "mapiHttp" {
			if v.MailStore.ExternalUrl != "" {
				return v.MailStore.ExternalUrl
			}
			return v.MailStore.InternalUrl
		}
	}
	return ""
}

// ExtractRPCURL extract the External RPC url from the autodiscover response
func ExtractRPCURL(resp *utils.AutodiscoverResp) string {
	for _, v := range resp.Response.Account.Protocol {
		if v.TypeAttr == "rpcHttp" {
			if v.MailStore.ExternalUrl != "" {
				return v.MailStore.ExternalUrl
			}
			return v.MailStore.InternalUrl
		}
	}
	return ""
}

// Init is used to start our mapi session
func Init(config *utils.Session, lid, URL, ABKURL string, transport int) {
	AuthSession = config
	AuthSession.LID = lid

	if transport == HTTP {
		AuthSession.URL, _ = url.Parse(URL)
		AuthSession.ABKURL, _ = url.Parse(ABKURL)
		if AuthSession.URL.Host == "outlook.office365.com" {
			AuthSession.Basic = true
		}
		if AuthSession.Basic == true {
			var Transport http.Transport
			if AuthSession.Proxy == "" {
				Transport = http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: AuthSession.Insecure},
				}
			} else {
				proxyURL, _ := url.Parse(AuthSession.Proxy)
				Transport = http.Transport{Proxy: http.ProxyURL(proxyURL),
					TLSClientConfig: &tls.Config{InsecureSkipVerify: AuthSession.Insecure},
				}
			}
			client = http.Client{Jar: AuthSession.CookieJar, Transport: &Transport}
		} else {
			client = http.Client{
				Transport: &httpntlm.NtlmTransport{
					Domain:    AuthSession.Domain,
					User:      AuthSession.User,
					Password:  AuthSession.Pass,
					NTHash:    AuthSession.NTHash,
					Insecure:  AuthSession.Insecure,
					CookieJar: AuthSession.CookieJar,
					Proxy:     AuthSession.Proxy,
					Hostname:  AuthSession.Hostname,
				},
				Jar: AuthSession.CookieJar,
			}
		}
	} else {
		AuthSession.URL, _ = url.Parse(AuthSession.RPCURL)
		AuthSession.Host = URL
	}
	AuthSession.Transport = transport
	AuthSession.ClientSet = false
	AuthSession.ReqCounter = 1
	AuthSession.LogonID = 0x0C
	AuthSession.Authenticated = false

	//default to Encrypt + Sign for NTLM
	AuthSession.RPCNetworkAuthLevel = rpchttp.RPC_C_AUTHN_LEVEL_PKT_PRIVACY
	AuthSession.RPCNetworkAuthType = rpchttp.RPC_C_AUTHN_WINNT

	if AuthSession.URL.Host == "outlook.office365.com" || AuthSession.RPCEncrypt == false {
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

// sendMapiRequest sends an Execute request, gets the response and processes.
// returns the unmarshalled ExecuteResponse and/or and error
func sendMapiRequest(mapi ExecuteRequest) (*ExecuteResponse, error) {
	var rawResp []byte
	var err error
	if AuthSession.Transport == HTTP { //this is always going to be an "Execute" request
		if rawResp, err = mapiRequestHTTP(AuthSession.URL.String(), "Execute", mapi.Marshal()); err != nil {
			if rawResp != nil {
				utils.Debug.Printf("%s\n", hex.Dump(rawResp))
			}
			return nil, err
		}
	} else {
		if rawResp, err = mapiRequestRPC(mapi); err != nil {
			if rawResp != nil {
				utils.Debug.Printf("%s\n", hex.Dump(rawResp))
			}
			return nil, err
		}
	}
	//debug flag

	executeResponse := ExecuteResponse{}
	err = executeResponse.Unmarshal(rawResp)

	if executeResponse.ErrorCode == 255 || err != nil {
		utils.Debug.Printf("%s\n", hex.Dump(rawResp))
		return nil, ErrNonZeroStatus
	}

	if len(executeResponse.RopBuffer.Body) == 0 {
		return nil, ErrEmptyBuffer
	}

	return &executeResponse, nil
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

// func sendMapiConnectHTTP(mapi Conn)
// mapiAuthRequest connects and authenticates using NTLM or basic auth.
// After the authentication is complete, we can simply use the mapiRequest
// and the session cookies.
func mapiRequestHTTP(URL, mapiType string, body []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", URL, bytes.NewReader(body))
	addMapiHeaders(req, mapiType)
	req.Header.Add("User-Agent", AuthSession.UserAgent)
	if AuthSession.Basic == true {
		if AuthSession.Domain != "" {
			req.SetBasicAuth(AuthSession.Domain+"\\"+AuthSession.User, AuthSession.Pass)
		} else {
			req.SetBasicAuth(AuthSession.Email, AuthSession.Pass)
		}
	}
	req.Close = true

	//request the auth url
	resp, err := client.Do(req)

	if err != nil {
		//check if this error was because of ntlm auth when basic auth was expected.
		if m, _ := regexp.Match("illegal base64", []byte(err.Error())); m == true {
			resp, err = client.Do(req)
		} else {
			return nil, err //&TransportError{err}
		}
	}

	defer resp.Body.Close()

	if resp == nil {
		return nil, &TransportError{fmt.Errorf("Empty HTTP Response")}
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		var authMethods []string
		var currentAuthMethod string
		var found = false

		if AuthSession.Basic == true {
			currentAuthMethod = "Basic"
		} else {
			currentAuthMethod = "NTLM"
		}

		for _, header := range resp.Header[http.CanonicalHeaderKey("WWW-Authenticate")] {
			authMethods = append(authMethods, header)

			if strings.HasPrefix(header, currentAuthMethod) {
				found = true
			}
		}

		if !found {
			if AuthSession.Verbose == true {
				utils.Trace.Printf("Available authentication scheme(s): %s", strings.Join(authMethods, ", "))
			}

			err := "It looks like that this authentication scheme is not supported"
			if AuthSession.Basic == true {
				err += ". Try to remove --basic option or specify --rpc option"
			}

			return nil, fmt.Errorf(err)
		}
	}

	rbody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &TransportError{err}
	}
	responseBody, err := readResponse(resp.Header, rbody)

	return responseBody, err
}

func mapiConnectRPC(body ConnectRequestRPC) ([]byte, error) {
	rpchttp.AuthSession = AuthSession
	ready := make(chan bool)      //this is our ready channel,
	chanError := make(chan error) //get the error message from our channel setup

	utils.Trace.Println("Setting up channels")
	//we should add a channel to check if there was an error setting up the channels
	//there will currently be a deadlock here if something goes wrong
	go rpchttp.RPCOpen(AuthSession.RPCURL, ready, chanError)

	//wait for channels to be setup
	if v := <-ready; v == false { //check if the setup was successful or premission Denied
		e := <-chanError
		return nil, &TransportError{fmt.Errorf("Couldn't setup RPC channel - %s", e)}
	}

	utils.Info.Println("Binding to RPC")
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

// mapiRequestRPC to our target. Takes the mapiType (Connect, Execute) to determine the
// action performed on the server side
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

	//we should do some proper responses here, rather than simply skipping 44 bytes ahead
	return resp, err
}

// isAuthenticated checks if we have a session
func isAuthenticated() {
	if AuthSession.CookieJar.Cookies(AuthSession.URL) == nil {
		utils.Info.Println("No authentication cookies found. You may not be authenticated.")
		utils.Info.Println("Trying to authenticate you")
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
		if headers.Get("X-ResponseCode") == "10" {
			utils.Error.Println("This is a server-side issue. See details at https://github.com/sensepost/ruler/issues/75")
		}
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

// Authenticate is used to create the MAPI session, get's session cookie etc
func Authenticate() (*RopLogonResponse, error) {
	if AuthSession.Transport == RPC {
		return AuthenticateRPC()
	}
	return AuthenticateHTTP()
}

// AuthenticateRPC does RPC version of authenticate
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

	connRequest.DNHash = utils.Hash(AuthSession.LID) //calculate unique 32bit hash of LID
	connRequest.CbLimit = 0x00
	connRequest.DefaultCodePage = 1252
	connRequest.LcidSort = 1033
	connRequest.LcidString = 1033
	connRequest.IcxrLink = 0xFFFFFFFF
	connRequest.FCanConvertCodePage = 0x1
	connRequest.ClientVersion = []byte{0x0f, 0x00, 0x03, 0x13, 0xe8, 0x03}
	connRequest.TimeStamp = 0x00

	if _, err := mapiConnectRPC(connRequest); err != nil {
		return nil, &TransportError{fmt.Errorf("An error occurred setting up RPC. %s", err)}
	}

	utils.Trace.Printf("User DN: %s", string(connRequest.UserDN))
	utils.Trace.Println("Got Context, Doing ROPLogin")

	AuthSession.UserDN = append([]byte(AuthSession.LID), []byte{0x00}...)
	return AuthenticateFetchMailbox(AuthSession.UserDN) //connRequest.UserDN)

}

// AuthenticateHTTP does the authenctication, seems like RPC/HTTP and MAPI/HTTP has slightly different auths
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
		return nil, &TransportError{err}
	}
	connResponse := ConnectResponse{}
	connResponse.Unmarshal(responseBody)

	if connResponse.StatusCode == 0 {
		utils.Trace.Printf("User DN: %s", string(connRequest.UserDN))
		utils.Trace.Println("Got Context, Doing ROPLogin")

		AuthSession.UserDN = connRequest.UserDN
		return AuthenticateFetchMailbox(connRequest.UserDN)
	}

	return nil, ErrUnknown
}

// AuthenticateFetchMailbox func to perform step two of the authentication process
func AuthenticateFetchMailbox(essdn []byte) (*RopLogonResponse, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()

	logonBody := RopLogonRequest{RopID: 0xFE, LogonID: AuthSession.LogonID}
	logonBody.OutputHandleIndex = 0x00
	logonBody.LogonFlags = 0x01
	if AuthSession.Admin == true {
		logonBody.OpenFlags = UseAdminPrivilege | TakeOwnership | UserPerMdbReplidMapping
	} else {
		logonBody.OpenFlags = UserPerMdbReplidMapping | HomeLogon | TakeOwnership
	}
	logonBody.StoreState = 0
	logonBody.Essdn = essdn
	logonBody.EssdnSize = uint16(len(logonBody.Essdn))
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = logonBody.Marshal()

	execResponse, err := sendMapiRequest(execRequest)
	//need to verify admin here...
	if err != nil {
		if AuthSession.Admin {
			return nil, ErrNotAdmin
		}
		return nil, &TransportError{err}
	}

	AuthSession.Authenticated = true

	logonResponse := RopLogonResponse{}
	logonResponse.Unmarshal(execResponse.RopBuffer.Body)

	if len(logonResponse.FolderIds) == 0 {
		if AuthSession.Admin {
			return nil, fmt.Errorf("Unable to retrieve mailbox as admin")
		}
		return nil, fmt.Errorf("Unable to retrieve mailbox as user")
	}
	specialFolders(logonResponse.FolderIds)
	return &logonResponse, nil
}

// Disconnect function to be nice and disconnect us from the server
// This is strictly necessary but hey... lets follow protocol
func Disconnect() (int, error) {
	//check if we actually authenticated and need to close our session
	if AuthSession == nil || AuthSession.Authenticated == false {
		return -1, nil //no session
	}

	utils.Trace.Println("And disconnecting from server")

	disconnectBody := DisconnectRequest{}
	disconnectBody.AuxilliaryBufSize = 0

	if _, err := sendMapiDisconnect(disconnectBody); err != nil {
		return -1, &TransportError{err}
	}

	return 0, nil
}

// ReleaseObject issues a RopReleaseRequest to free a server handle to an object
func ReleaseObject(inputHandle byte) (*RopReleaseResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()
	ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandleIndex: inputHandle}
	fullReq := ropRelease.Marshal()
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = fullReq

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	ropReleaseResponse := RopReleaseResponse{}
	if _, e := ropReleaseResponse.Unmarshal(execResponse.RopBuffer.Body); e != nil {
		return nil, e
	}
	return &ropReleaseResponse, nil

}

// ReadPerUserInformation issues a RopReleaseRequest to free a server handle to an object
func ReadPerUserInformation(folerID []byte) (*RopReadPerUserInformationResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()

	readRequest := RopReadPerUserInformationRequest{RopID: 0x63, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01}
	readRequest.FolderID = folerID
	readRequest.DataOffset = 0
	readRequest.MaxDataSize = 0xFF

	fullReq := readRequest.Marshal()

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = fullReq

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	readResponse := RopReadPerUserInformationResponse{}
	rops := []RopResponse{&readResponse}
	_, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)
	return &readResponse, e

}

// GetLongTermIDFromID issues a request for the long term ID of an Object
func GetLongTermIDFromID(objectID []byte) (*RopLongTermIDFromIDResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()

	longTermIDRequest := RopLongTermIDFromIDRequest{RopID: 0x43, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01}
	longTermIDRequest.ObjectID = objectID

	fullReq := longTermIDRequest.Marshal()

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = fullReq

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	longTermResponse := RopLongTermIDFromIDResponse{}
	rops := []RopResponse{&longTermResponse}
	_, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)
	return &longTermResponse, e

}

// SendExistingMessage sends a message that has already been created. This is essentially a RopSubmitMessage
func SendExistingMessage(folderID, messageID []byte, recipient string) (*RopSubmitMessageResponse, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()

	getMessage := RopOpenMessageRequest{RopID: 0x03, LogonID: AuthSession.LogonID}
	getMessage.InputHandleIndex = 0x00
	getMessage.OutputHandleIndex = 0x01
	getMessage.FolderID = folderID
	getMessage.MessageID = messageID
	getMessage.CodePageID = 0xFFF
	getMessage.OpenModeFlags = 0x03 //BestAccess

	fullReq := getMessage.Marshal()

	modRecipients := RopModifyRecipientsRequest{RopID: 0x0E, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01}
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
	modRecipients.RecipientRows[0] = ModifyRecipientRow{RowID: 1, RecipientType: 1}
	modRecipients.RecipientRows[0].RecipientRow = RecipientRow{}
	modRecipients.RecipientRows[0].RecipientRow.RecipientFlags = 0x0008 | 0x0003 | 0x0200 | 0x0010 | 0x3 | 0x0020
	modRecipients.RecipientRows[0].RecipientRow.EmailAddress = utils.UniString(recipient)   //email address
	modRecipients.RecipientRows[0].RecipientRow.DisplayName = utils.UniString("Self")       //Display name
	modRecipients.RecipientRows[0].RecipientRow.SimpleDisplayName = utils.UniString("Self") //Display name
	modRecipients.RecipientRows[0].RecipientRow.RecipientColumnCount = modRecipients.ColumnCount

	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties = StandardPropertyRow{Flag: 0x00}

	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray = make([][]byte, modRecipients.RecipientRows[0].RecipientRow.RecipientColumnCount)
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[0] = []byte{0x06, 0x00, 0x00, 0x00}
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[1] = []byte{0x00, 0x00, 0x00, 0x00}
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[2] = utils.UniString(recipient)
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[3] = []byte{0x00, 0x00, 0x00, 0x00}
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[4] = []byte{0x00, 0x00, 0x00, 0x40}
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[5] = utils.UniString("Self")
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[6] = []byte{0x01, 0x00, 0x00, 0x00}
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[7] = []byte{0x00, 0x00, 0x00, 0x00}

	modRecipients.RecipientRows[0].RecipientRowSize = uint16(len(utils.BodyToBytes(modRecipients.RecipientRows[0].RecipientRow)))
	fullReq = append(fullReq, modRecipients.Marshal()...)

	submitMessage := RopSubmitMessageRequest{RopID: 0x32, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01, SubmitFlags: 0x00}
	fullReq = append(fullReq, submitMessage.Marshal()...)

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = fullReq

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	getMessageResponse := RopOpenMessageResponse{}
	modRecipientsResponse := RopModifyRecipientsResponse{}
	submitMessageResp := RopSubmitMessageResponse{}
	rops := []RopResponse{&getMessageResponse, &modRecipientsResponse, &submitMessageResp}
	_, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)

	return &submitMessageResp, e

}

// SendMessage func to create a new message on the Exchange server
// and then sends an email to the target using their own email
func SendMessage(triggerWord, body string) (*RopSubmitMessageResponse, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()

	createMessage := RopCreateMessageRequest{RopID: 0x06, LogonID: AuthSession.LogonID}
	createMessage.InputHandleIndex = 0x00
	createMessage.OutputHandleIndex = 0x01
	createMessage.FolderID = AuthSession.Folderids[OUTBOX]
	createMessage.CodePageID = 0xFFF
	createMessage.AssociatedFlag = 0

	fullReq := createMessage.Marshal()

	setProperties := RopSetPropertiesRequest{RopID: 0x0A, LogonID: AuthSession.LogonID}
	setProperties.InputHandleIndex = 0x01
	setProperties.PropertValueCount = 9

	propertyTags := make([]TaggedPropertyValue, setProperties.PropertValueCount)
	propertyTags[0] = TaggedPropertyValue{PidTagBody, utils.UniString(fmt.Sprintf("%s\n\r", body))}
	propertyTags[1] = TaggedPropertyValue{PropertyTag{PtypString, 0x001A}, utils.UniString("IPM.Note")}
	propertyTags[2] = TaggedPropertyValue{PidTagMessageFlags, utils.EncodeNum(uint32(8))} //[]byte{0x00, 0x00, 0x00, 0x08}} //unsent
	propertyTags[3] = TaggedPropertyValue{PidTagConversationTopic, utils.UniString(triggerWord)}
	propertyTags[4] = TaggedPropertyValue{PropertyTag: PidTagIconIndex, PropertyValue: utils.EncodeNum(uint32(1))} //[]byte{0x00, 0x00, 0x00, 0x01}}
	propertyTags[5] = TaggedPropertyValue{PropertyTag: PidTagMessageEditorFormat, PropertyValue: []byte{0x01, 0x00, 0x00, 0x00}}
	propertyTags[5] = TaggedPropertyValue{PidTagNativeBody, utils.EncodeNum(uint32(1))} //[]byte{0x00, 0x00, 0x00, 0x01}}
	propertyTags[6] = TaggedPropertyValue{PidTagSubject, utils.UniString(triggerWord)}
	propertyTags[7] = TaggedPropertyValue{PidTagNormalizedSubject, utils.UniString(triggerWord)}
	propertyTags[8] = TaggedPropertyValue{PidTagHidden, []byte{0x01}} //hide message during "composition"

	setProperties.PropertyValues = propertyTags
	propertySize := 0
	for _, p := range propertyTags {
		propertySize += len(utils.BodyToBytes(p))
	}

	setProperties.PropertValueSize = uint16(propertySize + 2)

	fullReq = append(fullReq, setProperties.Marshal()...)

	modRecipients := RopModifyRecipientsRequest{RopID: 0x0E, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01}
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
	modRecipients.RecipientRows[0] = ModifyRecipientRow{RowID: 1, RecipientType: 1}
	modRecipients.RecipientRows[0].RecipientRow = RecipientRow{}
	modRecipients.RecipientRows[0].RecipientRow.RecipientFlags = 0x0008 | 0x0003 | 0x0200 | 0x0010 | 0x3 | 0x0020
	modRecipients.RecipientRows[0].RecipientRow.EmailAddress = utils.UniString(AuthSession.Email) //email address
	modRecipients.RecipientRows[0].RecipientRow.DisplayName = utils.UniString("Self")             //Display name
	modRecipients.RecipientRows[0].RecipientRow.SimpleDisplayName = utils.UniString("Self")       //Display name
	modRecipients.RecipientRows[0].RecipientRow.RecipientColumnCount = modRecipients.ColumnCount

	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties = StandardPropertyRow{Flag: 0x00}

	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray = make([][]byte, modRecipients.RecipientRows[0].RecipientRow.RecipientColumnCount)
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[0] = utils.EncodeNum(uint32(6)) //[]byte{0x00, 0x00, 0x00, 0x06}
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[1] = utils.EncodeNum(uint32(0)) //[]byte{0x00, 0x00, 0x00, 0x00}
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[2] = utils.UniString(AuthSession.Email)
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[3] = utils.EncodeNum(uint32(0))  //[]byte{0x00, 0x00, 0x00, 0x00}
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[4] = utils.EncodeNum(uint32(64)) //[]byte{0x00, 0x00, 0x00, 0x40}
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[5] = utils.UniString("Self")
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[6] = []byte{0x01, 0x00, 0x00, 0x00}
	modRecipients.RecipientRows[0].RecipientRow.RecipientProperties.ValueArray[7] = utils.EncodeNum(uint32(0)) //[]byte{0x00, 0x00, 0x00, 0x00}

	modRecipients.RecipientRows[0].RecipientRowSize = uint16(len(utils.BodyToBytes(modRecipients.RecipientRows[0].RecipientRow)))
	fullReq = append(fullReq, modRecipients.Marshal()...)

	submitMessage := RopSubmitMessageRequest{RopID: 0x32, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01, SubmitFlags: 0x00}
	fullReq = append(fullReq, submitMessage.Marshal()...)

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = fullReq

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	createMessageResponse := RopCreateMessageResponse{}
	propertiesResponse := RopSetPropertiesResponse{}
	modRecipientsResponse := RopModifyRecipientsResponse{}
	submitMessageResp := RopSubmitMessageResponse{}

	rops := []RopResponse{&createMessageResponse, &propertiesResponse, &modRecipientsResponse, &submitMessageResp}
	_, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)

	return &submitMessageResp, e
}

// SetMessageStatus is used to create a message on the exchange server
func SetMessageStatus(folderid, messageid []byte) (*RopSetMessageStatusResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()

	getFolder := RopOpenFolderRequest{RopID: 0x02, LogonID: AuthSession.LogonID}
	getFolder.InputHandleIndex = 0x00
	getFolder.OutputHandleIndex = 0x01
	getFolder.FolderID = folderid
	getFolder.OpenModeFlags = 0x00

	fullReq := getFolder.Marshal()

	setMessageStatus := RopSetMessageStatusRequest{RopID: 0x20, LogonID: AuthSession.LogonID}
	setMessageStatus.InputHandleIndex = 0x01
	setMessageStatus.MessageID = messageid
	setMessageStatus.MessageStatusFlags = PidTagMessageFlags
	setMessageStatus.MessageStatusMask = MSRemoteDelete

	fullReq = append(fullReq, setMessageStatus.Marshal()...)

	ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01}
	fullReq = append(fullReq, ropRelease.Marshal()...)

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = fullReq

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	setStatusResp := RopSetMessageStatusResponse{}
	rops := []RopResponse{&setStatusResp}
	_, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)
	return &setStatusResp, e

}

// GetPropertyIds returns the specific fields from a message
func GetPropertyIds(folderid, messageid []byte, propids []PropertyName) (*RopGetPropertyIdsFromNamesResponse, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()

	getMessage := RopOpenMessageRequest{RopID: 0x03, LogonID: AuthSession.LogonID}
	getMessage.InputHandleIndex = 0x00
	getMessage.OutputHandleIndex = 0x01
	getMessage.FolderID = folderid
	getMessage.MessageID = messageid
	getMessage.CodePageID = 0xFFF
	getMessage.OpenModeFlags = 0x03

	fullReq := getMessage.Marshal()

	getPropertyIds := RopGetPropertyIdsFromNamesRequest{}
	getPropertyIds.RopID = 0x56
	getPropertyIds.LogonID = AuthSession.LogonID
	getPropertyIds.InputHandleIndex = 0x01
	getPropertyIds.Flags = 0x02
	getPropertyIds.PropertyNameCount = uint16(len(propids))
	getPropertyIds.PropertyNames = propids

	fullReq = append(fullReq, getPropertyIds.Marshal()...)

	execRequest.RopBuffer.ROP.RopsList = fullReq
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF}

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	getMessageResponse := RopOpenMessageResponse{}
	getPropertyIdsResp := RopGetPropertyIdsFromNamesResponse{}
	rops := []RopResponse{&getMessageResponse, &getPropertyIdsResp}
	_, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)
	return &getPropertyIdsResp, e

}

// GetPropertyIdsList returns the list of properties on a message
func GetPropertyIdsList(folderid, messageid []byte) (*RopGetPropertiesListResponse, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()

	getMessage := RopOpenMessageRequest{RopID: 0x03, LogonID: AuthSession.LogonID}
	getMessage.InputHandleIndex = 0x00
	getMessage.OutputHandleIndex = 0x01
	getMessage.FolderID = folderid
	getMessage.MessageID = messageid
	getMessage.CodePageID = 0xFFF
	getMessage.OpenModeFlags = 0x03

	fullReq := getMessage.Marshal()

	getPropertyIds := RopGetPropertiesListRequest{RopID: 0x09, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01}

	fullReq = append(fullReq, getPropertyIds.Marshal()...)

	execRequest.RopBuffer.ROP.RopsList = fullReq
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF}

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	getMessageResponse := RopOpenMessageResponse{}
	getPropertyIdsResp := RopGetPropertiesListResponse{}
	rops := []RopResponse{&getMessageResponse, &getPropertyIdsResp}
	_, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)

	return &getPropertyIdsResp, e

}

// GetPropertyNamesFromID returns the property names for a set of ids
func GetPropertyNamesFromID(folderid, messageid, propids []byte, idcount int) (*RopGetNamesFromPropertyIdsResponse, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()

	getMessage := RopOpenMessageRequest{RopID: 0x03, LogonID: AuthSession.LogonID}
	getMessage.InputHandleIndex = 0x00
	getMessage.OutputHandleIndex = 0x01
	getMessage.FolderID = folderid
	getMessage.MessageID = messageid
	getMessage.CodePageID = 0xFFF
	getMessage.OpenModeFlags = 0x03

	fullReq := getMessage.Marshal()

	getPropNames := RopGetNamesFromPropertyIdsRequest{RopID: 0x55, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01}
	getPropNames.PropertyIDCount = uint16(idcount)
	getPropNames.PropertyIDs = propids

	fullReq = append(fullReq, getPropNames.Marshal()...)

	execRequest.RopBuffer.ROP.RopsList = fullReq
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF}

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	getMessageResponse := RopOpenMessageResponse{}
	getPropNamesResp := RopGetNamesFromPropertyIdsResponse{}
	rops := []RopResponse{&getMessageResponse, &getPropNamesResp}
	_, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)

	return &getPropNamesResp, e

}

// SetSearchCriteria function is used to set the search criteria on a folder or set of folders
func SetSearchCriteria(folderids, searchFolder []byte, restrictions Restriction) (*RopSetSearchCriteriaResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()

	getFolder := RopOpenFolderRequest{RopID: 0x02, LogonID: AuthSession.LogonID}
	getFolder.InputHandleIndex = 0x00
	getFolder.OutputHandleIndex = 0x01
	getFolder.FolderID = searchFolder
	getFolder.OpenModeFlags = 0x00

	fullReq := getFolder.Marshal()

	setCriteria := RopSetSearchCriteriaRequest{RopID: 0x30, LogonID: AuthSession.LogonID}
	setCriteria.InputHandleIndex = 0x01

	setCriteria.RestrictionData = restrictions.Marshal()

	setCriteria.RestrictDataSize = uint16(len(setCriteria.RestrictionData))
	setCriteria.FolderIds = folderids
	setCriteria.FolderIDCount = uint16(len(folderids) / 8)
	setCriteria.SearchFlags = RESTARTSEARCH | SHALLOWSEARCH | NONCONTENTINDEXEDSEARCH

	fullReq = append(fullReq, setCriteria.Marshal()...)

	execRequest.RopBuffer.ROP.RopsList = fullReq
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF}

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	openFolderResponse := RopOpenFolderResponse{}
	setCriteriaResponse := RopSetSearchCriteriaResponse{}
	rops := []RopResponse{&openFolderResponse, &setCriteriaResponse}
	_, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)

	return &setCriteriaResponse, e

}

// GetSearchCriteria function is used to set the search criteria on a folder or set of folders
func GetSearchCriteria(searchFolder []byte) (*RopGetSearchCriteriaResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()

	getFolder := RopOpenFolderRequest{RopID: 0x02, LogonID: AuthSession.LogonID}
	getFolder.InputHandleIndex = 0x00
	getFolder.OutputHandleIndex = 0x01
	getFolder.FolderID = searchFolder
	getFolder.OpenModeFlags = 0x00

	fullReq := getFolder.Marshal()

	getCriteria := RopGetSearchCriteriaRequest{RopID: 0x31, LogonID: AuthSession.LogonID}
	getCriteria.InputHandleIndex = 0x01
	getCriteria.UseUnicode = 0x01
	getCriteria.IncludeFolders = 0x00
	getCriteria.IncludeRestriction = 0x00

	fullReq = append(fullReq, getCriteria.Marshal()...)

	execRequest.RopBuffer.ROP.RopsList = fullReq
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF}

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	openFolderResponse := RopOpenFolderResponse{}
	getCriteriaResponse := RopGetSearchCriteriaResponse{}
	rops := []RopResponse{&openFolderResponse, &getCriteriaResponse}
	_, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)

	return &getCriteriaResponse, e

}

// SetFolderProperties is used to set one or more properties on a folder
func SetFolderProperties(folderid []byte, propertyTags []TaggedPropertyValue) (*RopSetPropertiesResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()

	getFolder := RopOpenFolderRequest{RopID: 0x02, LogonID: AuthSession.LogonID}
	getFolder.InputHandleIndex = 0x00
	getFolder.OutputHandleIndex = 0x01
	getFolder.FolderID = folderid
	getFolder.OpenModeFlags = 0x00

	fullReq := getFolder.Marshal()

	setProperties := RopSetPropertiesRequest{RopID: 0x0A, LogonID: AuthSession.LogonID}
	setProperties.InputHandleIndex = 0x01
	setProperties.PropertValueCount = 1

	setProperties.PropertyValues = propertyTags
	propertySize := 0
	for _, p := range propertyTags {
		propertySize += len(utils.BodyToBytes(p))
	}

	setProperties.PropertValueSize = uint16(propertySize + 2)

	fullReq = append(fullReq, setProperties.Marshal()...)

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = fullReq

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	openFolderResponse := RopOpenFolderResponse{}
	propertiesResponse := RopSetPropertiesResponse{}
	rops := []RopResponse{&openFolderResponse, &propertiesResponse}
	_, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)

	return &propertiesResponse, e

}

// CreateMessage creates a standard message for a folder
func CreateMessage(folderID []byte, properties []TaggedPropertyValue) (*RopSaveChangesMessageResponse, error) {
	return CreateMessageRequest(folderID, properties, 0)
}

// CreateAssocMessage creates a message that is associated with a folder
func CreateAssocMessage(folderID []byte, properties []TaggedPropertyValue) (*RopSaveChangesMessageResponse, error) {
	return CreateMessageRequest(folderID, properties, 1)
}

// CreateMessageRequest is used to create a message on the exchange server
func CreateMessageRequest(folderID []byte, properties []TaggedPropertyValue, associated byte) (*RopSaveChangesMessageResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()

	createMessage := RopCreateMessageRequest{RopID: 0x06, LogonID: AuthSession.LogonID}
	createMessage.InputHandleIndex = 0x00
	createMessage.OutputHandleIndex = 0x01
	createMessage.FolderID = folderID
	createMessage.CodePageID = 0xFFF
	createMessage.AssociatedFlag = associated

	fullReq := createMessage.Marshal()

	setProperties := RopSetPropertiesRequest{RopID: 0x0A, LogonID: AuthSession.LogonID}
	setProperties.InputHandleIndex = 0x01
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
	saveMessage.InputHandleIndex = 0x01
	saveMessage.SaveFlags = 0x02

	fullReq = append(fullReq, saveMessage.Marshal()...)

	ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01}
	fullReq = append(fullReq, ropRelease.Marshal()...)

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = fullReq

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	createMessageResponse := RopCreateMessageResponse{}
	propertiesResponse := RopSetPropertiesResponse{}
	saveMessageResponse := RopSaveChangesMessageResponse{}
	rops := []RopResponse{&createMessageResponse, &propertiesResponse, &saveMessageResponse}
	_, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)

	return &saveMessageResponse, e

}

// CreateMessageAttachment creates the attachment object for a message. If the message is attached by reference,
// no more actions are required. If the attachment data should be included in the message, this needs to be added with
// the WriteAttachmentProperty using the PidTagAttachDataBinary property
func CreateMessageAttachment(folderid, messageid []byte, properties []TaggedPropertyValue) (*RopCreateAttachmentResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()

	ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01}
	fullReq := ropRelease.Marshal()

	getMessage := RopOpenMessageRequest{RopID: 0x03, LogonID: AuthSession.LogonID}
	getMessage.InputHandleIndex = 0x00
	getMessage.OutputHandleIndex = 0x01
	getMessage.FolderID = folderid
	getMessage.MessageID = messageid
	getMessage.CodePageID = 0xFFF
	getMessage.OpenModeFlags = 0x03

	fullReq = append(fullReq, getMessage.Marshal()...)
	getAttachmentTbl := RopGetAttachmentTableRequest{RopID: 0x21, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01, OutputHandleIndex: 0x02, TableFlags: 0x00}
	createAttachment := RopCreateAttachmentRequest{RopID: 0x023, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01, OutputHandleIndex: 0x02}

	fullReq = append(fullReq, getAttachmentTbl.Marshal()...)
	fullReq = append(fullReq, createAttachment.Marshal()...)

	setProperties := RopSetPropertiesRequest{RopID: 0x0A, LogonID: AuthSession.LogonID}
	setProperties.InputHandleIndex = 0x02
	setProperties.PropertValueCount = uint16(len(properties))
	propertyTags := properties
	setProperties.PropertyValues = propertyTags
	propertySize := 0
	for _, p := range propertyTags {
		propertySize += len(utils.BodyToBytes(p))
	}

	setProperties.PropertValueSize = uint16(propertySize + 2)
	fullReq = append(fullReq, setProperties.Marshal()...)

	saveAttachment := RopSaveChangesAttachmentRequest{RopID: 0x25, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01, ResponseHandleIndex: 0x02, SaveFlags: 0x0A}
	fullReq = append(fullReq, saveAttachment.Marshal()...)

	saveMessage := RopSaveChangesMessageRequest{RopID: 0x0C, LogonID: AuthSession.LogonID}
	saveMessage.ResponseHandleIndex = 0x02
	saveMessage.InputHandleIndex = 0x01
	saveMessage.SaveFlags = 0x02

	fullReq = append(fullReq, saveMessage.Marshal()...)

	ropRelease = RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandleIndex: 0x00}
	ropRelease = RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01}
	fullReq = append(fullReq, ropRelease.Marshal()...)
	ropRelease = RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandleIndex: 0x02}
	fullReq = append(fullReq, ropRelease.Marshal()...)

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = fullReq

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	getMessageResp := RopOpenMessageResponse{}
	getAttachmentTblResp := RopGetAttachmentTableResponse{}
	createAttachmentResp := RopCreateAttachmentResponse{}
	propertiesResponse := RopSetPropertiesResponse{}
	saveAttachmentResp := RopSaveChangesAttachmentResponse{}
	saveMessageResponse := RopSaveChangesMessageResponse{}
	rops := []RopResponse{&getMessageResp, &getAttachmentTblResp, &createAttachmentResp, &propertiesResponse, &saveAttachmentResp, &saveMessageResponse}
	_, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)

	return &createAttachmentResp, e

}

// WriteAttachmentProperty opens a stream on an attachment property and writes to it
func WriteAttachmentProperty(folderid, messageid []byte, attachmentid uint32, propertyTag PropertyTag, propData []byte) (*RopSaveChangesAttachmentResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()

	ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01}
	fullReq := ropRelease.Marshal()

	getMessage := RopOpenMessageRequest{RopID: 0x03, LogonID: AuthSession.LogonID}
	getMessage.InputHandleIndex = 0x00
	getMessage.OutputHandleIndex = 0x01
	getMessage.FolderID = folderid
	getMessage.MessageID = messageid
	getMessage.CodePageID = 0xFFF
	getMessage.OpenModeFlags = 0x03

	fullReq = append(fullReq, getMessage.Marshal()...)
	getAttachmentTbl := RopGetAttachmentTableRequest{RopID: 0x21, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01, OutputHandleIndex: 0x02, TableFlags: 0x00}
	getAttachment := RopOpenAttachmentRequest{RopID: 0x022, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01, OutputHandleIndex: 0x02, OpenAttachmentFlags: 0x01, AttachmentID: attachmentid}

	fullReq = append(fullReq, getAttachmentTbl.Marshal()...)
	fullReq = append(fullReq, getAttachment.Marshal()...)

	openStream := RopOpenStreamRequest{RopID: 0x02B, LogonID: AuthSession.LogonID, InputHandleIndex: 0x02, OutputHandleIndex: 0x03, PropertyTag: propertyTag, OpenModeFlags: 0x01}

	fullReq = append(fullReq, openStream.Marshal()...)

	setStreamSize := RopSetStreamSizeRequest{RopID: 0x02F, LogonID: AuthSession.LogonID, InputHandleIndex: 0x03}
	setStreamSize.StreamSize = uint64(len(propData))

	fullReq = append(fullReq, setStreamSize.Marshal()...)

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = fullReq

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	getMessageResp := RopOpenMessageResponse{}
	getAttachmentTblResp := RopGetAttachmentTableResponse{}
	getAttachmentResp := RopOpenAttachmentResponse{}
	openStreamResp := RopOpenStreamResponse{}
	setStreamSizeResp := RopSetStreamSizeResponse{}

	rops := []RopResponse{&getMessageResp, &getAttachmentTblResp, &getAttachmentResp, &openStreamResp, &setStreamSizeResp}
	_, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)

	if e != nil {
		return nil, e
	}

	serverHandles := execResponse.RopBuffer.Body[len(execResponse.RopBuffer.Body)-12:]
	//messageHandles := execResponse.RopBuffer[len(execResponse.RopBuffer)-12:]
	utils.Debug.Printf("Starting Upload")
	//lets split it..
	index := 0
	split := 3000
	piecescnt := len(propData) / split
	for kk := 0; kk < piecescnt; kk++ {
		utils.Debug.Printf("Writing %d of %d", kk, piecescnt)
		var body []byte
		if index+split < len(propData) {
			body = propData[index : index+split]
		}
		index += split

		execRequest := ExecuteRequest{}
		execRequest.Init()

		writeStream := RopWriteStreamRequest{RopID: 0x2D, LogonID: AuthSession.LogonID, InputHandleIndex: 0x03}
		writeStream.DataSize = uint16(len(body))
		writeStream.Data = body

		fullReq = writeStream.Marshal()

		execRequest.RopBuffer.ROP.ServerObjectHandleTable = append([]byte{0x00, 0x00, 0x00, AuthSession.LogonID}, serverHandles...) //[]byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} //
		execRequest.RopBuffer.ROP.ServerObjectHandleTable = append(execRequest.RopBuffer.ROP.ServerObjectHandleTable, []byte{0xFF, 0xFF, 0xFF, 0xFF}...)
		execRequest.RopBuffer.ROP.RopsList = fullReq

		_, err := sendMapiRequest(execRequest)

		if err != nil {
			return nil, &TransportError{err}
		}

	}
	if len(propData) < split || piecescnt == 0 || len(propData) >= split*piecescnt {
		utils.Debug.Printf("Writing final piece %d of %d", piecescnt, piecescnt)
		body := propData[index:]
		execRequest := ExecuteRequest{}
		execRequest.Init()
		writeStream := RopWriteStreamRequest{RopID: 0x2D, LogonID: AuthSession.LogonID, InputHandleIndex: 0x03}
		writeStream.DataSize = uint16(len(body))
		writeStream.Data = body

		fullReq = writeStream.Marshal()

		execRequest.RopBuffer.ROP.ServerObjectHandleTable = append([]byte{0x00, 0x00, 0x00, AuthSession.LogonID}, serverHandles...) //[]byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		execRequest.RopBuffer.ROP.ServerObjectHandleTable = append(execRequest.RopBuffer.ROP.ServerObjectHandleTable, []byte{0xFF, 0xFF, 0xFF, 0xFF}...)
		execRequest.RopBuffer.ROP.RopsList = fullReq

		_, err := sendMapiRequest(execRequest)

		if err != nil {
			return nil, &TransportError{err}
		}

	}

	execRequest = ExecuteRequest{}
	execRequest.Init()

	commitStream := RopCommitStreamRequest{RopID: 0x5D, LogonID: AuthSession.LogonID, InputHandleIndex: 0x03}

	fullReq = commitStream.Marshal()

	saveAttachment := RopSaveChangesAttachmentRequest{RopID: 0x25, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01, ResponseHandleIndex: 0x02, SaveFlags: 0x0A}
	fullReq = append(fullReq, saveAttachment.Marshal()...)

	saveMessage := RopSaveChangesMessageRequest{RopID: 0x0C, LogonID: AuthSession.LogonID}
	saveMessage.ResponseHandleIndex = 0x02
	saveMessage.InputHandleIndex = 0x01
	saveMessage.SaveFlags = 0x02

	fullReq = append(fullReq, saveMessage.Marshal()...)

	ropRelease = RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01}
	fullReq = append(fullReq, ropRelease.Marshal()...)

	ropRelease = RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandleIndex: 0x02}
	fullReq = append(fullReq, ropRelease.Marshal()...)

	ropRelease = RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandleIndex: 0x03}
	fullReq = append(fullReq, ropRelease.Marshal()...)

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = append([]byte{0x00, 0x00, 0x00, AuthSession.LogonID}, serverHandles...) //[]byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = append(execRequest.RopBuffer.ROP.ServerObjectHandleTable, []byte{0xFF, 0xFF, 0xFF, 0xFF}...)
	execRequest.RopBuffer.ROP.RopsList = fullReq

	execResponse, err = sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	commitStreamResp := RopCommitStreamResponse{}
	saveAttachmentResp := RopSaveChangesAttachmentResponse{}
	saveMessageResponse := RopSaveChangesMessageResponse{}
	rops = []RopResponse{&commitStreamResp, &saveAttachmentResp, &saveMessageResponse}
	_, e = UnmarshalRops(execResponse.RopBuffer.Body, rops)

	return &saveAttachmentResp, e

}

// SetMessageProperties is used to update the properties of a message
func SetMessageProperties(folderid, messageid []byte, propertyTags []TaggedPropertyValue) (*RopSaveChangesMessageResponse, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()

	getMessage := RopOpenMessageRequest{RopID: 0x03, LogonID: AuthSession.LogonID}
	getMessage.InputHandleIndex = 0x00
	getMessage.OutputHandleIndex = 0x01
	getMessage.FolderID = folderid
	getMessage.MessageID = messageid
	getMessage.CodePageID = 0xFFF
	getMessage.OpenModeFlags = 0x03

	fullReq := getMessage.Marshal()

	setProperties := RopSetPropertiesRequest{RopID: 0x0A, LogonID: AuthSession.LogonID}
	setProperties.InputHandleIndex = 0x01
	setProperties.PropertValueCount = uint16(len(propertyTags))
	setProperties.PropertyValues = propertyTags
	propertySize := 0
	for _, p := range propertyTags {
		propertySize += len(utils.BodyToBytes(p))
	}

	setProperties.PropertValueSize = uint16(propertySize + 2)

	fullReq = append(fullReq, setProperties.Marshal()...)

	saveMessage := RopSaveChangesMessageRequest{RopID: 0x0C, LogonID: AuthSession.LogonID}
	saveMessage.ResponseHandleIndex = 0x02
	saveMessage.InputHandleIndex = 0x01
	saveMessage.SaveFlags = 0x02

	fullReq = append(fullReq, saveMessage.Marshal()...)

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = fullReq

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	getMessageResp := RopOpenMessageResponse{}
	propertiesResponse := RopSetPropertiesResponse{}
	saveMessageResponse := RopSaveChangesMessageResponse{}
	rops := []RopResponse{&getMessageResp, &propertiesResponse, &saveMessageResponse}
	_, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)

	return &saveMessageResponse, e

}

// SetPropertyFast is used to create a message on the exchange server through a the RopFastTransferSourceGetBufferRequest
func SetPropertyFast(folderid []byte, messageid []byte, property TaggedPropertyValue) (*RopSaveChangesMessageResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()

	ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01}
	fullReq := ropRelease.Marshal()

	getMessage := RopOpenMessageRequest{RopID: 0x03, LogonID: AuthSession.LogonID}
	getMessage.InputHandleIndex = 0x00
	getMessage.OutputHandleIndex = 0x01
	getMessage.FolderID = folderid
	getMessage.MessageID = messageid
	getMessage.CodePageID = 0xFFF
	getMessage.OpenModeFlags = 0x03

	fullReq = append(fullReq, getMessage.Marshal()...)

	fastTransfer := RopFastTransferDestinationConfigureRequest{RopID: 0x53, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01, OutputHandleIndex: 0x02, SourceOperation: 0x01, CopyFlags: 0x01}
	fullReq = append(fullReq, fastTransfer.Marshal()...)

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = fullReq

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	//we probably need to get the handles here to pass them down into the ServerObjectHandleTable
	serverHandles := execResponse.RopBuffer.Body[len(execResponse.RopBuffer.Body)-8:]
	messageHandles := serverHandles

	props := utils.BodyToBytes(property)

	//lets split it..
	index := 0
	split := 9000
	piecescnt := len(props) / split
	for kk := 0; kk < piecescnt; kk++ {
		var body []byte
		if index+split < len(props) {
			body = props[index : index+split]
		}
		index += split
		//fmt.Printf("%x\n", body)
		execRequest := ExecuteRequest{}
		execRequest.Init()
		setFast := RopFastTransferDestinationPutBufferRequest{RopID: 0x54, LogonID: AuthSession.LogonID, InputHandleIndex: 0x02, TransferDataSize: uint16(len(body)), TransferData: body}
		fullReq := setFast.Marshal()

		execRequest.RopBuffer.ROP.ServerObjectHandleTable = append([]byte{0x00, 0x00, 0x00, AuthSession.LogonID}, serverHandles...) //[]byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} //
		execRequest.RopBuffer.ROP.ServerObjectHandleTable = append(execRequest.RopBuffer.ROP.ServerObjectHandleTable, []byte{0xFF, 0xFF, 0xFF, 0xFF}...)
		execRequest.RopBuffer.ROP.RopsList = fullReq

		execResponse, err := sendMapiRequest(execRequest)

		if err != nil {
			return nil, &TransportError{err}
		}

		serverHandles = execResponse.RopBuffer.Body[len(execResponse.RopBuffer.Body)-8:]
	}
	if len(props) > split*piecescnt {
		body := props[index:]
		execRequest := ExecuteRequest{}
		execRequest.Init()
		setFast := RopFastTransferDestinationPutBufferRequest{RopID: 0x54, LogonID: AuthSession.LogonID, InputHandleIndex: 0x02, TransferDataSize: uint16(len(body)), TransferData: body}
		fullReq := setFast.Marshal()

		execRequest.RopBuffer.ROP.ServerObjectHandleTable = append([]byte{0x00, 0x00, 0x00, AuthSession.LogonID}, serverHandles...) //[]byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		execRequest.RopBuffer.ROP.ServerObjectHandleTable = append(execRequest.RopBuffer.ROP.ServerObjectHandleTable, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}...)
		execRequest.RopBuffer.ROP.RopsList = fullReq

		_, err := sendMapiRequest(execRequest)

		if err != nil {
			return nil, &TransportError{err}
		}

	}
	return SaveMessageFast(0x01, 0x02, messageHandles)

}

// SaveMessageFast uses the RopFastTransfer buffers to save a message
func SaveMessageFast(inputHandle, responseHandle byte, serverHandles []byte) (*RopSaveChangesMessageResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()

	saveMessage := RopSaveChangesMessageRequest{RopID: 0x0C, LogonID: AuthSession.LogonID}
	saveMessage.ResponseHandleIndex = responseHandle
	saveMessage.InputHandleIndex = inputHandle
	saveMessage.SaveFlags = 0x02

	fullReq := saveMessage.Marshal()

	ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandleIndex: inputHandle}
	fullReq = append(fullReq, ropRelease.Marshal()...)

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = append([]byte{0x00, 0x00, 0x00, AuthSession.LogonID}, serverHandles...) //[]byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = append(execRequest.RopBuffer.ROP.ServerObjectHandleTable, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}...)
	execRequest.RopBuffer.ROP.RopsList = fullReq

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	saveMessageResponse := RopSaveChangesMessageResponse{}
	rops := []RopResponse{&saveMessageResponse}
	_, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)
	return &saveMessageResponse, e

}

// DeleteMessages is used to delete a message on the exchange server
func DeleteMessages(folderid []byte, messageIDCount int, messageIDs []byte) (*RopDeleteMessagesResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()

	getFolder := RopOpenFolderRequest{RopID: 0x02, LogonID: AuthSession.LogonID}
	getFolder.InputHandleIndex = 0x00
	getFolder.OutputHandleIndex = 0x01
	getFolder.FolderID = folderid
	getFolder.OpenModeFlags = 0x00

	fullReq := getFolder.Marshal()
	//Normal delete 0x1E, hard-delete 0x91
	deleteMessages := RopDeleteMessagesRequest{RopID: 0x91, LogonID: AuthSession.LogonID}
	deleteMessages.InputHandleIndex = 0x01
	deleteMessages.WantSynchronous = 255
	deleteMessages.NotifyNonRead = 0
	deleteMessages.MessageIDCount = uint16(messageIDCount)
	deleteMessages.MessageIDs = messageIDs

	fullReq = append(fullReq, deleteMessages.Marshal()...)

	ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01}
	fullReq = append(fullReq, ropRelease.Marshal()...)

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = fullReq

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	openFolderResponse := RopOpenFolderResponse{}
	deleteMessageResponse := RopDeleteMessagesResponse{}
	rops := []RopResponse{&openFolderResponse, &deleteMessageResponse}
	_, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)

	return &deleteMessageResponse, e

}

// OpenAttachment allows for opening the attachment associated with a message
func OpenAttachment(folderid, messageid []byte, attachid uint32, columns []PropertyTag) (*RopFastTransferSourceGetBufferResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()

	ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01}
	fullReq := ropRelease.Marshal()

	getMessage := RopOpenMessageRequest{RopID: 0x03, LogonID: AuthSession.LogonID}
	getMessage.InputHandleIndex = 0x00
	getMessage.OutputHandleIndex = 0x01
	getMessage.FolderID = folderid
	getMessage.MessageID = messageid
	getMessage.CodePageID = 0xFFF
	getMessage.OpenModeFlags = 0x03

	fullReq = append(fullReq, getMessage.Marshal()...)

	getAttachmentTbl := RopGetAttachmentTableRequest{RopID: 0x21, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01, OutputHandleIndex: 0x02, TableFlags: 0x00}
	getAttachment := RopOpenAttachmentRequest{RopID: 0x022, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01, OutputHandleIndex: 0x02, OpenAttachmentFlags: 0x01, AttachmentID: attachid}

	fullReq = append(fullReq, getAttachmentTbl.Marshal()...)
	fullReq = append(fullReq, getAttachment.Marshal()...)

	fastTransfer := RopFastTransferSourceCopyPropertiesRequest{RopID: 0x69, LogonID: AuthSession.LogonID, InputHandleIndex: 0x02, OutputHandleIndex: 0x03}
	fastTransfer.Level = 0
	fastTransfer.CopyFlags = 2
	fastTransfer.SendOptions = 1
	fastTransfer.PropertyTagCount = uint16(len(columns))
	fastTransfer.PropertyTags = columns

	fullReq = append(fullReq, fastTransfer.Marshal()...)

	fastTransferBuffer := RopFastTransferSourceGetBufferRequest{RopID: 0x4E, LogonID: AuthSession.LogonID, InputHandleIndex: 0x03}
	fastTransferBuffer.BufferSize = 0xBABE
	fastTransferBuffer.MaximumBufferSize = 0xBABE

	fullReq = append(fullReq, fastTransferBuffer.Marshal()...)

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = fullReq

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	getMessageResponse := RopOpenMessageResponse{}
	getAttachmentTblResp := RopGetAttachmentTableResponse{}
	getAttachmentResp := RopOpenAttachmentResponse{}
	propsResponse := RopFastTransferSourceCopyPropertiesResponse{}
	ppropsResponse := RopFastTransferSourceGetBufferResponse{}
	rops := []RopResponse{&getMessageResponse, &getAttachmentTblResp, &getAttachmentResp, &propsResponse, &ppropsResponse}
	bufPtr, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)
	if e != nil {
		return nil, e
	}
	//Rop release if we are done.. otherwise get rest of stream
	if ppropsResponse.TransferStatus == 0x0001 {
		buff, _ := FastTransferFetchStep(execResponse.RopBuffer.Body[bufPtr:])

		if buff != nil {
			ppropsResponse.TransferBuffer = append(ppropsResponse.TransferBuffer, buff...)
		}
	}

	ReleaseObject(0x01)
	return &ppropsResponse, e

}

// GetAttachments retrieves all the valid attachment IDs for a message
func GetAttachments(folderid, messageid []byte) (*RopGetValidAttachmentsResponse, error) {
	return nil, fmt.Errorf("This function is not working at present. Weird response from exchange: Invalid rop type found: GetValidAttachments")
	/*
		execRequest := ExecuteRequest{}
		execRequest.Init()

		ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01}
		fullReq := ropRelease.Marshal()

		getMessage := RopOpenMessageRequest{RopID: 0x03, LogonID: AuthSession.LogonID}
		getMessage.InputHandleIndex = 0x00
		getMessage.OutputHandleIndex = 0x01
		getMessage.FolderID = folderid
		getMessage.MessageID = messageid
		getMessage.CodePageID = 0xFFF
		getMessage.OpenModeFlags = 0x03

		fullReq = append(fullReq, getMessage.Marshal()...)
		getAttachmentTbl := RopGetAttachmentTableRequest{RopID: 0x21, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01, OutputHandleIndex: 0x02, TableFlags: 0x00}
		getAttachments := RopGetValidAttachmentsRequest{RopID: 0x52, LogonID: AuthSession.LogonID, InputHandleIndex: 0x00}

		fullReq = append(fullReq, getAttachmentTbl.Marshal()...)
		fullReq = append(fullReq, getAttachments.Marshal()...)
		//fullReq := getAttachments.Marshal()

		execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		execRequest.RopBuffer.ROP.RopsList = fullReq

		execResponse, err := sendMapiRequest(execRequest)

		if err != nil {
			return nil, &TransportError{err}
		}

			bufPtr := 0
			var p int
			var e error

			getMessageResp := RopOpenMessageResponse{}
			if p, e = getMessageResp.Unmarshal(execResponse.RopBuffer.Body[bufPtr:]); e != nil {
				return nil, e
			}
			bufPtr += p

			getAttachmentTblResp := RopGetAttachmentTableResponse{}
			if p, e = getAttachmentTblResp.Unmarshal(execResponse.RopBuffer.Body[bufPtr:]); e != nil {
				return nil, e
			}
			bufPtr += p

			getAttachmentsResp := RopGetValidAttachmentsResponse{}
			if p, e = getAttachmentsResp.Unmarshal(execResponse.RopBuffer.Body[bufPtr:]); e != nil {
				return nil, e
			}
			return &getAttachmentsResp, nil
	*/
}

// EmptyFolder is used to delete all contents of a folder
func EmptyFolder(folderid []byte) (*RopEmptyFolderResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()

	getFolder := RopOpenFolderRequest{RopID: 0x02, LogonID: AuthSession.LogonID}
	getFolder.InputHandleIndex = 0x00
	getFolder.OutputHandleIndex = 0x01
	getFolder.FolderID = folderid
	getFolder.OpenModeFlags = 0x00

	fullReq := getFolder.Marshal()

	emptyFolder := RopEmptyFolderRequest{RopID: 0x58, LogonID: AuthSession.LogonID}
	emptyFolder.InputHandleIndex = 0x01
	emptyFolder.WantAsynchronous = 255
	emptyFolder.WantDeleteAssociated = 255

	fullReq = append(fullReq, emptyFolder.Marshal()...)

	ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01}
	fullReq = append(fullReq, ropRelease.Marshal()...)

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = fullReq

	execResponse, err := sendMapiRequest(execRequest)
	if err != nil {
		return nil, &TransportError{err}
	}

	openFolderResponse := RopOpenFolderResponse{}
	emptyFolderResponse := RopEmptyFolderResponse{}
	rops := []RopResponse{&openFolderResponse, &emptyFolderResponse}
	_, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)

	return &emptyFolderResponse, e

}

// DeleteFolder is used to delete  a folder
func DeleteFolder(parentFolder, folderid []byte) (*RopDeleteFolderResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()

	getFolder := RopOpenFolderRequest{RopID: 0x02, LogonID: AuthSession.LogonID}
	getFolder.InputHandleIndex = 0x00
	getFolder.OutputHandleIndex = 0x01
	getFolder.FolderID = parentFolder
	getFolder.OpenModeFlags = 0x00

	fullReq := getFolder.Marshal()

	deleteFolder := RopDeleteFolderRequest{RopID: 0x1D, LogonID: AuthSession.LogonID}
	deleteFolder.InputHandleIndex = 0x01
	deleteFolder.FolderID = folderid
	deleteFolder.DeleteFolderFlags = 0x10 | 0x04 | 0x01

	fullReq = append(fullReq, deleteFolder.Marshal()...)

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = fullReq

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	openFolderResponse := RopOpenFolderResponse{}
	deleteFolderResponse := RopDeleteFolderResponse{}
	rops := []RopResponse{&openFolderResponse, &deleteFolderResponse}
	_, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)
	return &deleteFolderResponse, e

}

// GetFolder for backwards compatibility
// This function will be replaced in newer versions
func GetFolder(folderid int, columns []PropertyTag) (*RopOpenFolderResponse, error) {
	folderID := AuthSession.Folderids[folderid]
	folderResp, _, e := GetFolderFromID(folderID, nil)
	return folderResp, e
}

// GetFolderProps function get's a folder from the folders id
// FolderIds can be any of the "specialFolders" as defined in Exchange
// mapi/datastructs.go folder id/locations constants
func GetFolderProps(folderid int, columns []PropertyTag) (*RopOpenFolderResponse, *RopGetPropertiesSpecificResponse, error) {
	folderID := AuthSession.Folderids[folderid]
	return GetFolderFromID(folderID, columns)
}

// GetFolderFromID newer methods to actually allow using the folder id
func GetFolderFromID(folderid []byte, columns []PropertyTag) (*RopOpenFolderResponse, *RopGetPropertiesSpecificResponse, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()
	//execRequest.MaxRopOut = 262144

	getFolder := RopOpenFolderRequest{RopID: 0x02, LogonID: AuthSession.LogonID}
	getFolder.InputHandleIndex = 0x00
	getFolder.OutputHandleIndex = 0x01
	getFolder.FolderID = folderid
	getFolder.OpenModeFlags = 0x00

	var k []byte

	if columns != nil {
		getProperties := RopGetPropertiesSpecificRequest{}
		getProperties.RopID = 0x07
		getProperties.LogonID = AuthSession.LogonID
		getProperties.InputHandleIndex = 0x01
		getProperties.PropertySizeLimit = 0x00
		getProperties.WantUnicode = 0x01
		getProperties.PropertyTagCount = uint16(len(columns))
		getProperties.PropertyTags = columns

		k = append(getFolder.Marshal(), getProperties.Marshal()...)

	} else {
		k = getFolder.Marshal()
	}

	execRequest.RopBuffer.ROP.RopsList = k
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF}

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, nil, &TransportError{err}
	}

	openFolderResponse := RopOpenFolderResponse{}
	rops := []RopResponse{&openFolderResponse}
	bufPtr, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)

	if columns == nil || e != nil {
		return &openFolderResponse, nil, e
	}

	getPropertiesResponse := RopGetPropertiesSpecificResponse{}
	propRops := []GetProperties{&getPropertiesResponse}
	_, e = UnmarshalPropertyRops(execResponse.RopBuffer.Body[bufPtr:], propRops, columns)

	return &openFolderResponse, &getPropertiesResponse, e

}

// OpenMessage opens and returns a handle to a message
func OpenMessage(folderid, messageid []byte) ([]byte, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()

	ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01}
	fullReq := ropRelease.Marshal()

	getMessage := RopOpenMessageRequest{RopID: 0x03, LogonID: AuthSession.LogonID}
	getMessage.InputHandleIndex = 0x00
	getMessage.OutputHandleIndex = 0x01
	getMessage.FolderID = folderid
	getMessage.MessageID = messageid
	getMessage.CodePageID = 0xFFF
	getMessage.OpenModeFlags = 0x03

	fullReq = append(fullReq, getMessage.Marshal()...)
	execRequest.RopBuffer.ROP.RopsList = fullReq
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF}

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	bufPtr := 0

	var e error

	openMessage := RopOpenMessageResponse{}
	if _, e = openMessage.Unmarshal(execResponse.RopBuffer.Body[bufPtr:]); e != nil {
		return nil, e
	}
	return execResponse.RopBuffer.Body[len(execResponse.RopBuffer.Body)-4:], nil
}

// GetMessage returns the specific fields from a message
func GetMessage(folderid, messageid []byte, columns []PropertyTag) (GetProperties, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()

	ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01}
	fullReq := ropRelease.Marshal()

	getMessage := RopOpenMessageRequest{RopID: 0x03, LogonID: AuthSession.LogonID}
	getMessage.InputHandleIndex = 0x00
	getMessage.OutputHandleIndex = 0x01
	getMessage.FolderID = folderid
	getMessage.MessageID = messageid
	getMessage.CodePageID = 0xFFF
	getMessage.OpenModeFlags = 0x03

	fullReq = append(fullReq, getMessage.Marshal()...)

	if columns != nil {
		getProperties := RopGetPropertiesSpecificRequest{}
		getProperties.RopID = 0x07
		getProperties.LogonID = AuthSession.LogonID
		getProperties.InputHandleIndex = 0x01
		getProperties.PropertySizeLimit = 0x00
		getProperties.WantUnicode = 0x01
		getProperties.PropertyTagCount = uint16(len(columns))
		getProperties.PropertyTags = columns

		fullReq = append(fullReq, getProperties.Marshal()...)
	} else {
		getPropertiesAll := RopGetPropertiesAllRequest{}
		getPropertiesAll.RopID = 0x08
		getPropertiesAll.LogonID = AuthSession.LogonID
		getPropertiesAll.InputHandleIndex = 0x01
		getPropertiesAll.PropertySizeLimit = 0x00
		getPropertiesAll.WantUnicode = 0x01
		fullReq = append(fullReq, getPropertiesAll.Marshal()...)
	}
	//queryRows := RopQueryRowsRequest{RopID: 0x15, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01, QueryRowsFlags: 0x00, ForwardRead: 0x01, RowCount: 0x32}
	//k = append(k, queryRows.Marshal()...)
	ropRelease = RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01}
	fullReq = append(fullReq, ropRelease.Marshal()...)

	execRequest.RopBuffer.ROP.RopsList = fullReq
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF}

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	openMessageResponse := RopOpenMessageResponse{}
	rops := []RopResponse{&openMessageResponse}
	bufPtr, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)
	if e != nil {
		return nil, e
	}
	if columns != nil {
		props := RopGetPropertiesSpecificResponse{}
		propRops := []GetProperties{&props}
		_, e = UnmarshalPropertyRops(execResponse.RopBuffer.Body[bufPtr:], propRops, columns)
		return &props, e
	}

	props := RopGetPropertiesAllResponse{}
	propRops := []GetProperties{&props}
	_, e = UnmarshalPropertyRops(execResponse.RopBuffer.Body[bufPtr:], propRops, columns)
	return &props, e

}

// GetMessageFast returns the specific fields from a message using the fast transfer buffers. This works better for large messages
func GetMessageFast(folderid, messageid []byte, columns []PropertyTag) (*RopFastTransferSourceGetBufferResponse, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()

	ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01}
	fullReq := ropRelease.Marshal()

	getMessage := RopOpenMessageRequest{RopID: 0x03, LogonID: AuthSession.LogonID}
	getMessage.InputHandleIndex = 0x00
	getMessage.OutputHandleIndex = 0x01
	getMessage.FolderID = folderid
	getMessage.MessageID = messageid
	getMessage.CodePageID = 0xFFF
	getMessage.OpenModeFlags = 0x03

	fullReq = append(fullReq, getMessage.Marshal()...)

	fastTransfer := RopFastTransferSourceCopyPropertiesRequest{RopID: 0x69, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01, OutputHandleIndex: 0x02}
	fastTransfer.Level = 0
	fastTransfer.CopyFlags = 2
	fastTransfer.SendOptions = 1
	fastTransfer.PropertyTagCount = uint16(len(columns))
	fastTransfer.PropertyTags = columns

	fullReq = append(fullReq, fastTransfer.Marshal()...)

	fastTransferBuffer := RopFastTransferSourceGetBufferRequest{RopID: 0x4E, LogonID: AuthSession.LogonID, InputHandleIndex: 0x02}
	fastTransferBuffer.BufferSize = 0xBABE
	fastTransferBuffer.MaximumBufferSize = 0xBABE

	fullReq = append(fullReq, fastTransferBuffer.Marshal()...)

	execRequest.RopBuffer.ROP.RopsList = fullReq
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	openMessageResponse := RopOpenMessageResponse{}
	props := RopFastTransferSourceCopyPropertiesResponse{}
	pprops := RopFastTransferSourceGetBufferResponse{}
	rops := []RopResponse{&openMessageResponse, &props, &pprops}
	bufPtr, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)
	//Rop release if we are done.. otherwise get rest of stream
	if pprops.TransferStatus == 0x0001 {
		buff, err := FastTransferFetchStep(execResponse.RopBuffer.Body[bufPtr:])
		if err != nil {
			return nil, err
		}
		if buff != nil {
			pprops.TransferBuffer = append(pprops.TransferBuffer, buff...)
		}
	}

	ReleaseObject(0x01)

	return &pprops, e

}

// FastTransferFetchStep fetches the next part of a fast TransferBuffer
func FastTransferFetchStep(handles []byte) ([]byte, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()

	fastTransferBuffer := RopFastTransferSourceGetBufferRequest{RopID: 0x4E, LogonID: AuthSession.LogonID, InputHandleIndex: 0x02}
	fastTransferBuffer.BufferSize = 0xBABE
	fastTransferBuffer.MaximumBufferSize = 0xBABE

	fullReq := fastTransferBuffer.Marshal()

	execRequest.RopBuffer.ROP.RopsList = fullReq
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = append([]byte{0x00, 0x00, 0x00, AuthSession.LogonID}, handles...) //append(handles, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}...) //[]byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} //append([]byte{0x00, 0x00, 0x00, AuthSession.LogonID}, handles...)

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	pprops := RopFastTransferSourceGetBufferResponse{}
	rops := []RopResponse{&pprops}
	bufPtr, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)
	utils.Trace.Printf("Large transfer in progress. Status: %d", pprops.TransferStatus)

	if pprops.TransferStatus == 0x0001 {
		buff, err := FastTransferFetchStep(execResponse.RopBuffer.Body[bufPtr:])
		if err != nil {
			return nil, err
		}
		if buff != nil {
			pprops.TransferBuffer = append(pprops.TransferBuffer, buff...)

		}
	}

	return pprops.TransferBuffer, e

}

// GetContentsTable is the standard request for getting the contents of a table.
// A wrapper function that calls GetContentsTableRequest
func GetContentsTable(folderid []byte) (*RopGetContentsTableResponse, []byte, error) {
	return GetContentsTableRequest(folderid, 0x40)
}

// GetAssocatedContentsTable is the standard request for getting the contents of a table.
// sets the assocated flag to get hidden items
// A wrapper function that calls GetContentsTableRequest
func GetAssocatedContentsTable(folderid []byte) (*RopGetContentsTableResponse, []byte, error) {
	return GetContentsTableRequest(folderid, 0x40|0x02)
}

// GetContentsTableRequest function get's a folder from the folders id
// and returns a hanlde to the contents table for that folder. tableFlags can be used to
// control whether the associated table entries etc are returned
func GetContentsTableRequest(folderid []byte, tableFlags byte) (*RopGetContentsTableResponse, []byte, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()
	ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01}
	fullReq := ropRelease.Marshal()

	getFolder := RopOpenFolderRequest{RopID: 0x02, LogonID: AuthSession.LogonID}
	getFolder.InputHandleIndex = 0x00
	getFolder.OutputHandleIndex = 0x01
	getFolder.FolderID = folderid
	getFolder.OpenModeFlags = 0x00

	fullReq = append(fullReq, getFolder.Marshal()...)

	getContents := RopGetContentsTableRequest{RopID: 0x05, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01, OutputHandleIndex: 0x02, TableFlags: tableFlags}

	fullReq = append(fullReq, getContents.Marshal()...)

	execRequest.RopBuffer.ROP.RopsList = fullReq
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	//fetch contents
	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, nil, &TransportError{err}
	}

	if len(execResponse.RopBuffer.Body) == 0 {
		return nil, nil, fmt.Errorf("Empty table")
	}

	openFolderResponse := RopOpenFolderResponse{}
	ropContents := RopGetContentsTableResponse{}
	rops := []RopResponse{&openFolderResponse, &ropContents}
	bufPtr, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)

	return &ropContents, execResponse.RopBuffer.Body[bufPtr:], e

}

// GetFolderHierarchy function get's a folder from the folders id
// and returns a handle to the hierarchy table
func GetFolderHierarchy(folderid []byte) (*RopGetHierarchyTableResponse, []byte, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()
	execRequest.MaxRopOut = 262144

	getFolder := RopOpenFolderRequest{RopID: 0x02, LogonID: AuthSession.LogonID}
	getFolder.InputHandleIndex = 0x00
	getFolder.OutputHandleIndex = 0x01
	getFolder.FolderID = folderid
	getFolder.OpenModeFlags = 0x00
	fullReq := getFolder.Marshal()

	//set table flag as 0x04 | 0x40 (Depth and use unicode)
	getFolderHierarchy := RopGetHierarchyTableRequest{RopID: 0x04, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01, OutputHandleIndex: 0x02, TableFlags: 0x40}
	fullReq = append(fullReq, getFolderHierarchy.Marshal()...)

	execRequest.RopBuffer.ROP.RopsList = fullReq
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, nil, &TransportError{err}
	}

	openFolderResponse := RopOpenFolderResponse{}
	hierarchyTableResponse := RopGetHierarchyTableResponse{}
	rops := []RopResponse{&openFolderResponse, &hierarchyTableResponse}
	bufPtr, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)

	bufPtr += 8 //the serverhandle is the 3rd set of 4 bytes - we need this handle to access the hierarchy table

	return &hierarchyTableResponse, execResponse.RopBuffer.Body[bufPtr:], e

}

// GetSubFolders returns all the subfolders available in a folder
func GetSubFolders(folderid []byte) (*RopQueryRowsResponse, error) {
	folderHeirarchy, svrhndl, err := GetFolderHierarchy(folderid)
	if err != nil {
		return nil, err
	}

	execRequest := ExecuteRequest{}
	execRequest.Init()

	setColumns := RopSetColumnsRequest{RopID: 0x12, LogonID: AuthSession.LogonID}
	setColumns.InputHandleIndex = 0x01
	setColumns.PropertyTagCount = 2
	setColumns.PropertyTags = make([]PropertyTag, 2)
	setColumns.PropertyTags[0] = PidTagDisplayName
	setColumns.PropertyTags[1] = PidTagFolderID

	fullReq := setColumns.Marshal()

	queryRows := RopQueryRowsRequest{RopID: 0x15, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01, QueryRowsFlags: 0x00, ForwardRead: 0x01, RowCount: uint16(folderHeirarchy.RowCount)}
	fullReq = append(fullReq, queryRows.Marshal()...)
	execRequest.RopBuffer.ROP.RopsList = fullReq
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = append([]byte{0x01, 0x00, 0x00, AuthSession.LogonID}, svrhndl...)

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	setColumnsResp := RopSetColumnsResponse{}
	rops := []RopResponse{&setColumnsResp}
	bufPtr, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)
	if e != nil {
		return nil, e
	}
	rows := RopQueryRowsResponse{}
	//propRops := []GetProperties{&rows}
	//_, e = UnmarshalPropertyRops(execResponse.RopBuffer.Body[bufPtr:], propRops, setColumns.PropertyTags)
	if _, e = rows.Unmarshal(execResponse.RopBuffer.Body[bufPtr:], setColumns.PropertyTags); e != nil {
		return nil, e
	}
	return &rows, e

}

// CreateSearchFolder function to create a search folder
func CreateSearchFolder(folderName string) (*RopCreateFolderResponse, error) {
	return CreateFolderRequest(folderName, true, 0x02)
}

// CreateFolder function to create a search folder
func CreateFolder(folderName string, hidden bool) (*RopCreateFolderResponse, error) {
	return CreateFolderRequest(folderName, hidden, 0x01)
}

// CreateFolderRequest function to create a folder on the exchange server
func CreateFolderRequest(folderName string, hidden bool, ftype uint8) (*RopCreateFolderResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()
	execRequest.MaxRopOut = 262144

	createFolder := RopCreateFolderRequest{RopID: 0x1C, LogonID: AuthSession.LogonID, InputHandleIndex: 0x00, OutputHandleIndex: 0x01, Reserved: 0x00}
	createFolder.FolderType = ftype
	createFolder.UseUnicodeStrings = 0x01
	createFolder.OpenExisting = 0x00
	createFolder.DisplayName = utils.UniString(folderName)
	createFolder.Comment = utils.UniString("some comment")
	fullReq := createFolder.Marshal()

	//if we want to create a hidden folder (so it doesn't show up in Outlook)
	if hidden == true {
		setProperties := RopSetPropertiesRequest{RopID: 0x0A, LogonID: AuthSession.LogonID}
		setProperties.InputHandleIndex = 0x01
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

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, ErrTransport //&TransportError{err}
	}

	createFolderResponse := RopCreateFolderResponse{}
	rops := []RopResponse{&createFolderResponse}

	if hidden == true {
		propResp := RopSetPropertiesResponse{}
		rops = append(rops, &propResp)
	}
	_, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)
	return &createFolderResponse, e

}

// GetContents returns the rows of a folder's content table.
// This function returns the subject and message id
// For custom columns use GetContentsColumns
func GetContents(folderid []byte) (*RopQueryRowsResponse, error) {
	columns := make([]PropertyTag, 3)
	columns[0] = PidTagSubject
	columns[1] = PidTagMid
	columns[2] = PropertyTag{PtypString8, 0x80C7}
	return GetTableContents(folderid, false, columns)
}

// GetAssociatedContents returns the rows of a folder's assocated content table
func GetAssociatedContents(folderid []byte, columns []PropertyTag) (*RopQueryRowsResponse, error) {
	return GetTableContents(folderid, true, columns)
}

// GetContentsColumns returns the rows of a folder's content table
func GetContentsColumns(folderid []byte, columns []PropertyTag) (*RopQueryRowsResponse, error) {
	return GetTableContents(folderid, false, columns)
}

// GetTableContents returns the contents of a specific table
func GetTableContents(folderid []byte, assoc bool, columns []PropertyTag) (*RopQueryRowsResponse, error) {
	var contentsTable *RopGetContentsTableResponse
	var svrhndl []byte
	var err error
	var inputHndl uint8 = 0x03
	if assoc == false {
		contentsTable, svrhndl, err = GetContentsTable(folderid)
	} else {
		contentsTable, svrhndl, err = GetAssocatedContentsTable(folderid)
	}
	if err != nil || contentsTable == nil {
		return nil, err
	}

	execRequest := ExecuteRequest{}
	execRequest.Init()

	setColumns := RopSetColumnsRequest{RopID: 0x12, LogonID: AuthSession.LogonID, SetColumnFlags: 0x00}
	setColumns.InputHandleIndex = inputHndl
	setColumns.PropertyTagCount = uint16(len(columns))
	setColumns.PropertyTags = make([]PropertyTag, setColumns.PropertyTagCount)
	for k, v := range columns {
		setColumns.PropertyTags[k] = v
	}

	fullReq := setColumns.Marshal()

	queryRows := RopQueryRowsRequest{RopID: 0x15, LogonID: AuthSession.LogonID, InputHandleIndex: inputHndl, QueryRowsFlags: 0x00, ForwardRead: 0x01, RowCount: uint16(contentsTable.RowCount)}
	fullReq = append(fullReq, queryRows.Marshal()...)

	ropRelease := RopReleaseRequest{RopID: 0x01, LogonID: AuthSession.LogonID, InputHandleIndex: inputHndl}
	fullReq = append(fullReq, ropRelease.Marshal()...)

	execRequest.RopBuffer.ROP.RopsList = fullReq
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = append([]byte{0x01, 0x00, 0x00, AuthSession.LogonID}, svrhndl...)

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	setColumnsResp := RopSetColumnsResponse{}
	rops := []RopResponse{&setColumnsResp}
	bufPtr, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)
	if e != nil {
		return nil, e
	}
	rows := RopQueryRowsResponse{}
	propRops := []GetProperties{&rows}
	_, e = UnmarshalPropertyRops(execResponse.RopBuffer.Body[bufPtr:], propRops, setColumns.PropertyTags)

	return &rows, e

}

// DisplayRules function get's a folder from the folders id
// this is more of a wrapper to facilitate legacy code until I get around to changing it in ruler.go
func DisplayRules() ([]Rule, error) {
	cols := make([]PropertyTag, 2)
	cols[0] = PidTagRuleID
	cols[1] = PidTagRuleName
	rows, err := FetchRules(cols)
	if err != nil {
		return nil, err
	}

	rules := make([]Rule, int(rows.RowCount))

	for k := 0; k < int(rows.RowCount); k++ {
		rule := Rule{}
		rule.RuleID = rows.RowData[k][0].ValueArray
		rule.RuleName = rows.RowData[k][1].ValueArray
		rules[k] = rule
	}
	return rules, nil
}

// FetchRules function returns rules along with the associated columns
func FetchRules(columns []PropertyTag) (*RopQueryRowsResponse, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()

	getRulesFolder := RopGetRulesTableRequest{RopID: 0x3f, LogonID: AuthSession.LogonID, InputHandleIndex: 0x00, OutputHandleIndex: 0x01, TableFlags: 0x40}
	//RopSetColumns
	setColumns := RopSetColumnsRequest{RopID: 0x12, LogonID: AuthSession.LogonID}
	setColumns.InputHandleIndex = 0x01
	setColumns.PropertyTagCount = uint16(len(columns))
	setColumns.PropertyTags = columns

	//RopQueryRows
	queryRows := RopQueryRowsRequest{RopID: 0x15, LogonID: AuthSession.LogonID, InputHandleIndex: 0x01, QueryRowsFlags: 0x00, ForwardRead: 0x01, RowCount: 0x32}

	getRules := append(getRulesFolder.Marshal(), setColumns.Marshal()...)
	getRules = append(getRules, queryRows.Marshal()...)

	execRequest.RopBuffer.ROP.RopsList = getRules
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x01, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF}

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	rulesTableResponse := RopGetRulesTableResponse{}
	colsResponse := RopSetColumnsResponse{}
	rops := []RopResponse{&rulesTableResponse, &colsResponse}
	bufPtr, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)
	if e != nil {
		return nil, e
	}
	rows := RopQueryRowsResponse{}
	//TODO
	_, e = rows.Unmarshal(execResponse.RopBuffer.Body[bufPtr:], columns)
	if e != nil {
		return nil, e
	}

	return &rows, e

}

// ExecuteDeleteRuleAdd adds a new mailrule for deleting a message
// This should be merged with ExecuteMailRuleAdd
func ExecuteDeleteRuleAdd(rulename, triggerword string) (*ExecuteResponse, error) {
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

	//still uses old hardcoded data struct. we can change this going forward and use the
	//CRuleAction elements
	actionData := ActionData{}
	actionData.ActionElem = []byte{0x00, 0x00, 0x14}
	actionData.ActionName = utils.UTF16BE(rulename)
	//CRuleElement
	actionData.Element = []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x5F, 0x00, 0x00, 0x00, 0x05, 0x00, 0xff, 0xff, 0x00, 0x00, 0x0c, 0x00, 0x43, 0x52, 0x75, 0x6c, 0x65, 0x45, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x90, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x80, 0x64, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x80, 0xCD, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	actionData.Trigger = utils.UTF16BE(triggerword)
	actionData.Elem = []byte{0x01, 0x80, 0x4A, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x42, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	actionData.EndPoint = []byte{}

	ruleAction := RuleAction{Actions: 1, ActionType: 0x05, ActionFlavor: 0, ActionFlags: 0}
	ruleAction.ActionLen = uint16(len(utils.BodyToBytes(actionData)) + 9)
	ruleAction.ActionData = actionData

	pdat := ruleAction.Marshal()

	propertyValues[4] = TaggedPropertyValue{PidTagRuleActions, pdat}                              //PidTagRuleProvider
	propertyValues[5] = TaggedPropertyValue{PidTagRuleProvider, utils.UniString("RuleOrganizer")} //PidTagRuleLevel
	propertyValues[6] = TaggedPropertyValue{PidTagRuleLevel, []byte{0x00, 0x00, 0x00, 0x00}}      //PidTagRuleProviderData
	propertyValues[7] = TaggedPropertyValue{PidTagRuleProviderData, []byte{0x10, 0x00, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x28, 0x7d, 0xd2, 0x27, 0x14, 0xc4, 0xe4, 0x40}}
	//propertyValues[8] = TaggedPropertyValue{PidTagRuleUserFlags, []byte{0x0, 0x0, 0x0, 0xf}} //PidTagRuleSequence

	addRule.RuleData.PropertyValues = propertyValues
	addRule.RuleData.PropertyValueCount = uint16(len(propertyValues))

	ruleBytes := utils.BodyToBytes(addRule)
	execRequest.RopBuffer.ROP.RopsList = ruleBytes
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x01, 0x00, 0x00, AuthSession.LogonID} //append(AuthSession.RulesHandle, []byte{0xFF, 0xFF, 0xFF, 0xFF}...)

	_, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	return nil, err
}

// ExecuteMailRuleAdd adds a new mailrules
func ExecuteMailRuleAdd(rulename, triggerword, triggerlocation string, delete bool) (*ExecuteResponse, error) {
	//valid

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

	//still uses old hardcoded data struct. we can change this going forward and use the
	//CRuleAction elements
	actionData := ActionData{}
	actionData.ActionElem = []byte{0x00, 0x00, 0x14}
	actionData.ActionName = utils.UTF16BE(rulename)
	actionData.Element = []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa8, 0x00, 0x00}
	actionData.ActionCount = []byte{0x00, 0x06}
	actionData.CRuleElement = []byte{0x00, 0xff, 0xff, 0x00, 0x00, 0x0c, 0x00, 0x43, 0x52, 0x75, 0x6c, 0x65, 0x45, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x90, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	actionData.Told = []byte{0x01, 0x80, 0x64, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x80, 0xcd, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	actionData.Trigger = utils.UTF16BE(triggerword)
	actionData.Elem = []byte{0x01, 0x80, 0x49, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	actionData.EndPoint = append(utils.UTF16BE(triggerlocation), []byte{0x01, 0x80, 0x4a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x42, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)

	ruleAction := RuleAction{Actions: 1, ActionType: 0x05, ActionFlavor: 0, ActionFlags: 0}
	ruleAction.ActionLen = uint16(len(utils.BodyToBytes(actionData)) + 9)
	ruleAction.ActionData = actionData

	pdat := ruleAction.Marshal()

	propertyValues[4] = TaggedPropertyValue{PidTagRuleActions, pdat}                              //PidTagRuleProvider
	propertyValues[5] = TaggedPropertyValue{PidTagRuleProvider, utils.UniString("RuleOrganizer")} //PidTagRuleLevel
	propertyValues[6] = TaggedPropertyValue{PidTagRuleLevel, []byte{0x00, 0x00, 0x00, 0x00}}      //PidTagRuleProviderData
	propertyValues[7] = TaggedPropertyValue{PidTagRuleProviderData, []byte{0x10, 0x00, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x28, 0x7d, 0xd2, 0x27, 0x14, 0xc4, 0xe4, 0x40}}
	//propertyValues[8] = TaggedPropertyValue{PidTagRuleUserFlags, []byte{0x0, 0x0, 0x0, 0xf}} //PidTagRuleSequence

	addRule.RuleData.PropertyValues = propertyValues
	addRule.RuleData.PropertyValueCount = uint16(len(propertyValues))

	ruleBytes := utils.BodyToBytes(addRule)
	execRequest.RopBuffer.ROP.RopsList = ruleBytes
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x01, 0x00, 0x00, AuthSession.LogonID} //append(AuthSession.RulesHandle, []byte{0xFF, 0xFF, 0xFF, 0xFF}...)

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return nil, &TransportError{err}
	}

	return execResponse, nil
}

// ExecuteMailRuleDelete function to delete mailrules
func ExecuteMailRuleDelete(ruleid []byte) error {
	execRequest := ExecuteRequest{}
	execRequest.Init()

	delRule := RopModifyRulesRequest{RopID: 0x41, LoginID: AuthSession.LogonID, InputHandleIndex: 0x00, ModifyRulesFlag: 0x00, RulesCount: 0x01, RuleData: RuleData{}}
	delRule.RuleData.RuleDataFlags = 0x04
	delRule.RuleData.PropertyValueCount = 0x01
	delRule.RuleData.PropertyValues = make([]TaggedPropertyValue, 1)
	delRule.RuleData.PropertyValues[0] = TaggedPropertyValue{PidTagRuleID, ruleid}

	ruleBytes := utils.BodyToBytes(delRule)
	execRequest.RopBuffer.ROP.RopsList = ruleBytes
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x01, 0x00, 0x00, AuthSession.LogonID} //append(AuthSession.RulesHandle, []byte{0xFF, 0xFF, 0xFF, 0xFF}...)

	execResponse, err := sendMapiRequest(execRequest)

	if err != nil {
		return &TransportError{err}
	}

	//process the exec response
	delRuleResponse := RopModifyRulesResponse{}
	rops := []RopResponse{&delRuleResponse}
	_, e := UnmarshalRops(execResponse.RopBuffer.Body, rops)
	return e
}

// Ping send a PING message to the server
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

// DecodeBufferToRows returns the property rows contained in the buffer, takes a list
// of propertytags. These are needed to figure out how to split the columns in the rows
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
			fmt.Println("Got a Binary Row", cnt)
			pos = p
			trow.ValueArray, pos = utils.ReadBytes(pos, int(cnt), buff)
			rows = append(rows, trow)
		}
	}
	return rows
}
