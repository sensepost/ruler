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

//RCP over HTTP transport type for traditional MAPI
const RPC int = 2

//AuthSession a
var AuthSession Session

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
func mapiRequestRPC(URL string, body []byte) (*http.Response, []byte) {
	URL = "http://127.0.0.1:8081/rpc/rpcproxy.dll?7bb476d4-8e1f-4a57-bbd8-beac7912fb77@evilcorp.ninja:6001"
	rpchttp.AuthSession = session
	rpchttp.RPCInDataOpen(URL)
	/*
		if AuthSession.ClientSet == false {
			AuthSession.Client = http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
				Jar: AuthSession.CookieJar,
			}
			AuthSession.ClientSet = true
		}
		req, err := http.NewRequest("RPC_IN_DATA", URL, bytes.NewReader(body))
		addRPCHeaders(req)
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
		fmt.Println(req.Header)
		fmt.Println(resp)

		fmt.Println(rbody)
		return resp, rbody
	*/
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
	connRequest.Flags = uFlagsUser
	connRequest.DefaultCodePage = 1252
	connRequest.LcidSort = 2057
	connRequest.LcidString = 1033

	if AuthSession.Transport == HTTP {
		resp, rbody := mapiRequestHTTP(AuthSession.URL.String(), "Connect", BodyToBytes(connRequest))

		responseBody, err := readResponse(resp.Header, rbody)
		if err != nil {
			return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
		}
		connResponse := ConnectResponse{}
		connResponse.Unmarshal(responseBody)

		if connResponse.StatusCode == 0 {
			fmt.Println("[+] User DN: ", string(connRequest.UserDN))
			fmt.Println("[*] Got Context, Doing ROPLogin")
			return AuthenticateFetchMailbox(connRequest.UserDN)
		}
		return nil, fmt.Errorf("[x]Authentication failed with non-zero status code")
	} else {
		mapiRequestRPC("", BodyToBytes(connRequest))

	}
	return nil, fmt.Errorf("[x] An Unspecified error occurred")
}

//AuthenticateFetchMailbox func to perform step two of the authentication process
func AuthenticateFetchMailbox(essdn []byte) (*RopLogonResponse, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()

	logonBody := RopLogonRequest{}
	logonBody.RopID = 0xFE
	logonBody.LogonID = AuthSession.LogonID
	logonBody.OutputHandleIndex = 0x00
	logonBody.LogonFlags = 0x01
	logonBody.OpenFlags = []byte{0x0C, 0x04, 0x00, 0x21}
	logonBody.StoreState = []byte{0x00, 0x00, 0x00, 0x00}
	logonBody.Essdn = essdn
	logonBody.EssdnSize = uint16(len(logonBody.Essdn))
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0xFF, 0xFF, 0xFF, 0xFF}
	execRequest.RopBuffer.ROP.RopsList = BodyToBytes(logonBody)

	execRequest.CalcSizes()
	if AuthSession.Transport == HTTP { // HTTP
		resp, rbody := mapiRequestHTTP(AuthSession.URL.String(), "Execute", BodyToBytes(execRequest))
		responseBody, err := readResponse(resp.Header, rbody)

		if err != nil {
			return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
		}
		execResponse := ExecuteResponse{}
		execResponse.Unmarshal(responseBody)
		if execResponse.ErrorCode == 0 && len(responseBody) < 256 {
			AuthSession.Authenticated = true

			logonResponse := RopLogonResponse{}
			logonResponse.Unmarshal(execResponse.RopBuffer)
			AuthSession.Folderids = logonResponse.FolderIds

			return &logonResponse, nil
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
		resp, rbody := mapiRequestHTTP(AuthSession.URL.String(), "Disconnect", BodyToBytes(disconnectBody))
		_, err := readResponse(resp.Header, rbody)
		if err != nil {
			return -1, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
		}
	}
	return 0, nil
}

//ExecuteFetchMailRules fetches the current mailrules
func ExecuteFetchMailRules(messageID []byte) (*ExecuteResponse, error) {
	execRequest := ExecuteRequest{}
	execRequest.Init()
	execRequest.MaxRopOut = 262144
	cnt := 0
	var folder []byte
	for k := 0; k < 13; k++ {
		if k == 4 { //inbox
			folder = AuthSession.Folderids[cnt : cnt+8]
		}
		cnt += 8
	}

	getRulesOrganizer := []byte{0x01, AuthSession.LogonID, 0x00, 0x03, AuthSession.LogonID, 0x01, 0x02, 0xff, 0x0f}
	getRulesOrganizer = append(getRulesOrganizer, folder...)
	getRulesOrganizer = append(getRulesOrganizer, []byte{0x03}...)
	getRulesOrganizer = append(getRulesOrganizer, messageID...)
	getRulesOrganizer = append(getRulesOrganizer, []byte{0x2B, AuthSession.LogonID, 0x02, 0x03, 0x02, 0x01, 0x02, 0x68, 0x00, 0x2C, AuthSession.LogonID, 0x03, 0x00, 0x7C}...)

	execRequest.RopBuffer.ROP.RopsList = getRulesOrganizer
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x1A, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	execRequest.CalcSizes()
	//fetch rules
	if AuthSession.Transport == HTTP { // HTTP
		resp, rbody := mapiRequestHTTP(AuthSession.URL.String(), "Execute", BodyToBytes(execRequest))
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

//GetContentsTable function get's a folder from the folders id
func GetContentsTable() (*RopGetContentsTableResponse, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()
	execRequest.MaxRopOut = 262144

	getContents := []byte{0x05, AuthSession.LogonID, 0x00, 0x01, 0x02}
	getContents = append(getContents, []byte{0x12, AuthSession.LogonID, 0x01, 0x00, 0x06, 0x00, 0x14, 0x00, 0x48, 0x67, 0x14, 0x00, 0x4a, 0x67, 0x14, 0x00, 0x4d, 0x67, 0x03, 0x00, 0x4e, 0x67, 0x1f, 0x00, 0x1a, 0x00, 0x40, 0x00, 0x08, 0x30, 0x14, AuthSession.LogonID, 0x01, 0x00, 0x2e, 0x00, 0x04, 0x04, 0x1f, 0x00, 0x1a, 0x00, 0x1f, 0x00, 0x1a, 0x00, 0x49, 0x00, 0x50, 0x00, 0x4d, 0x00, 0x2e, 0x00, 0x52, 0x00, 0x75, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x4f, 0x00, 0x72, 0x00, 0x67, 0x00, 0x61, 0x00, 0x6e, 0x00, 0x69, 0x00, 0x7a, 0x00, 0x65, 0x00, 0x72, 0x00, 0x00, 0x00, 0x13, AuthSession.LogonID, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x08, 0x30, 0x01, 0x18, AuthSession.LogonID, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, AuthSession.LogonID, 0x01, 0x02, 0x01, 0x00, 0x10}...)

	execRequest.RopBuffer.ROP.RopsList = getContents

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x01, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF}

	execRequest.CalcSizes()
	//fetch contents
	if AuthSession.Transport == HTTP { // HTTP
		resp, rbody := mapiRequestHTTP(AuthSession.URL.String(), "Execute", BodyToBytes(execRequest))
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
func GetFolder() (*ExecuteResponse, error) {

	execRequest := ExecuteRequest{}
	execRequest.Init()

	cnt := 0
	var folder []byte
	for k := 0; k < 13; k++ {
		if k == 4 { //inbox
			folder = AuthSession.Folderids[cnt : cnt+8]
		}
		cnt += 8
	}

	getFolder := []byte{0x02, AuthSession.LogonID, 0x00, 0x01}
	getFolder = append(getFolder, folder...)
	getFolder = append(getFolder, []byte{0x00, 0x07, AuthSession.LogonID, 0x01, 0x00, 0x00, 0x01, 0x00, 0x21, 0x00, 0x14, 0x00, 0x49, 0x67, 0x03, 0x00, 0xf4, 0x0f, 0x02, 0x01, 0x72, 0x66, 0x1f, 0x00, 0xe5, 0x36, 0x1f, 0x00, 0xe6, 0x36, 0x1f, 0x00, 0x01, 0x30, 0x03, 0x00, 0x01, 0x36, 0x03, 0x00, 0x02, 0x36, 0x03, 0x00, 0x03, 0x36, 0x0b, 0x00, 0x0a, 0x36, 0x1f, 0x00, 0x13, 0x36, 0x02, 0x01, 0x16, 0x36, 0x02, 0x01, 0xd0, 0x36, 0x02, 0x01, 0xd1, 0x36, 0x02, 0x01, 0xd2, 0x36, 0x02, 0x01, 0xd3, 0x36, 0x02, 0x01, 0xd4, 0x36, 0x02, 0x01, 0xd5, 0x36, 0x02, 0x01, 0xd6, 0x36, 0x02, 0x01, 0xd7, 0x36, 0x02, 0x11, 0xd8, 0x36, 0x02, 0x01, 0xd9, 0x36, 0x03, 0x00, 0xde, 0x36, 0x02, 0x01, 0xdf, 0x36, 0x02, 0x01, 0xe0, 0x36, 0x03, 0x00, 0xe1, 0x36, 0x02, 0x11, 0xe4, 0x36, 0x02, 0x01, 0xeb, 0x36, 0x03, 0x00, 0x39, 0x66, 0x02, 0x01, 0xda, 0x36, 0x02, 0x01, 0x18, 0x30, 0x03, 0x00, 0x1e, 0x30, 0x02, 0x01, 0xda, 0x36}...)

	execRequest.RopBuffer.ROP.RopsList = getFolder

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x00, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF}

	execRequest.CalcSizes()
	//fetch folder
	if AuthSession.Transport == HTTP { // HTTP
		resp, rbody := mapiRequestHTTP(AuthSession.URL.String(), "Execute", BodyToBytes(execRequest))
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

	getFolder := []byte{0x3f, AuthSession.LogonID, 0x00, 0x01, 0x40}
	getFolder = append(getFolder, []byte{0x12, AuthSession.LogonID, 0x01, 0x00, 0x02, 0x00, 0x14, 0x00, 0x74, 0x66, 0x1f, 0x00, 0x82, 0x66}...)
	getFolder = append(getFolder, []byte{0x15, AuthSession.LogonID, 0x01, 0x00, 0x01, 0x32, 0x00}...)
	execRequest.RopBuffer.ROP.RopsList = getFolder

	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x01, 0x00, 0x00, AuthSession.LogonID, 0xFF, 0xFF, 0xFF, 0xFF}

	execRequest.CalcSizes()

	//fetch folder
	if AuthSession.Transport == HTTP { // HTTP
		resp, rbody := mapiRequestHTTP(AuthSession.URL.String(), "Execute", BodyToBytes(execRequest))
		responseBody, err := readResponse(resp.Header, rbody)
		if err != nil {
			return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
		}
		execResponse := ExecuteResponse{}
		execResponse.Unmarshal(responseBody)

		rules, _ := DecodeRulesResponse(execResponse.RopBuffer)
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

	addRule := ModRuleData{0x41, AuthSession.LogonID, 0x00, 0x00, uint16(1), RuleData{}}
	addRule.RuleData.RuleDataFlags = 0x01

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

	ruleAction := RuleAction{}
	ruleAction.Actions = 1
	ruleAction.ActionLen = uint16(len(BodyToBytes(actionData)) + 9)
	ruleAction.ActionType = 0x05 //DEFER
	ruleAction.ActionFlavor = 0
	ruleAction.ActionFlags = 0
	ruleAction.ActionData = actionData

	pdat := BodyToBytes(ruleAction)

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

	//execRequest.RopBuffer.ROP.RopsList = append([]byte{0x01, AuthSession.LogonID, 0x01}, ruleBytes...)
	execRequest.RopBuffer.ROP.RopsList = ruleBytes
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x01, 0x00, 0x00, AuthSession.LogonID} //append(AuthSession.RulesHandle, []byte{0xFF, 0xFF, 0xFF, 0xFF}...)

	execRequest.CalcSizes()

	if AuthSession.Transport == HTTP { // HTTP
		resp, rbody := mapiRequestHTTP(AuthSession.URL.String(), "Execute", BodyToBytes(execRequest))
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

	delRule := ModRuleData{0x41, AuthSession.LogonID, 0x00, 0x00, uint16(1), RuleData{}}
	delRule.RuleData.RuleDataFlags = 0x04
	delRule.RuleData.PropertyValueCount = uint16(1)
	delRule.RuleData.PropertyValues = make([]TaggedPropertyValue, 1)
	delRule.RuleData.PropertyValues[0] = TaggedPropertyValue{PidTagRuleId, ruleid}

	ruleBytes := BodyToBytes(delRule)
	execRequest.RopBuffer.ROP.RopsList = ruleBytes
	execRequest.RopBuffer.ROP.ServerObjectHandleTable = []byte{0x01, 0x00, 0x00, AuthSession.LogonID} //append(AuthSession.RulesHandle, []byte{0xFF, 0xFF, 0xFF, 0xFF}...)

	execRequest.CalcSizes()

	if AuthSession.Transport == HTTP { // HTTP
		resp, rbody := mapiRequestHTTP(AuthSession.URL.String(), "Execute", BodyToBytes(execRequest))
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
