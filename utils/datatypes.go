package utils

import (
	"encoding/xml"
	"net/http"
	"net/http/cookiejar"
	"net/url"
)

// Config containing the session variables
type Config struct {
	Domain    string
	User      string
	Pass      string
	Email     string
	Basic     bool
	Insecure  bool
	Verbose   bool
	Admin     bool
	Proxy     string
	UserAgent string
	Hostname  string
}

// Session stores authentication cookies etc
type Session struct {
	User          string
	Pass          string
	Email         string
	Domain        string
	Proxy         string
	UserAgent     string
	Basic         bool
	Insecure      bool
	Verbose       bool
	Admin         bool
	DiscoURL      *url.URL
	LID           string
	URL           *url.URL
	ABKURL        *url.URL //URL for the AddressBook Provider
	Host          string   //used for TCP
	ReqCounter    int
	Transport     int
	CookieJar     *cookiejar.Jar
	Client        http.Client
	ClientSet     bool
	LogonID       byte
	Authenticated bool
	Folderids     [][]byte
	RulesHandle   []byte
	Hostname      string
	NTHash        []byte
	NTLMAuth      string

	RPCSet              bool
	ContextHandle       []byte //16-byte cookie for the RPC session
	RPCURL              string
	UserDN              []byte
	Trigger             string
	RPCMailbox          string
	RPCEncrypt          bool
	RPCNtlm             bool
	RPCNetworkAuthLevel uint8
	RPCNetworkAuthType  uint8
	RPCNtlmSessionKey   []byte
}

// YamlConfig holds the data that a user supplies with a yaml config file
type YamlConfig struct {
	Username   string
	Email      string
	Password   string
	Hash       string
	Domain     string
	UserDN     string
	Mailbox    string
	RPCURL     string
	RPC        bool
	RPCEncrypt bool
	Ntlm       bool
	MapiURL    string
}

// AutodiscoverResp structure for unmarshal
type AutodiscoverResp struct {
	Response Response
}

// Response structure for unmarshal
type Response struct {
	User    User
	Account Account
	Error   AutoError
}

// AutoError structure for unmarshal
type AutoError struct {
	ErrorCode string
	Message   string
	DebugData string
}

// User structure for unmarshal
type User struct {
	DisplayName             string
	LegacyDN                string
	DeploymentID            string
	AutoDiscoverSMTPAddress string
}

// Account structure for unmarshal
type Account struct {
	AccountType     string
	Action          string
	RedirectAddr    string
	MicrosoftOnline bool
	Protocol        []*Protocol
}

// Protocol structure for unmarshal
type Protocol struct {
	Type                    string
	TypeAttr                string `xml:"Type,attr"`
	Server                  string
	TTL                     string
	ServerDN                string
	ServerVersion           string
	MdbDN                   string
	PublicFolderServer      string
	Port                    string
	DirectoryPort           string
	ReferralPort            string
	ASUrl                   string
	EWSUrl                  string
	EMWSUrl                 string
	SharingURL              string
	ECPUrl                  string
	OOFUrl                  string
	UMUrl                   string
	OABUrl                  string
	EwsPartnerURL           string
	LoginName               string
	DomainRequired          string
	DomainName              string
	SPA                     string
	AuthPackage             string
	CertPrincipleName       string
	SSL                     string
	AuthRequired            string
	UsePOPAuth              string
	SMTPLast                string
	NetworkRequirements     string
	MailStore               *MailStore
	AddressBook             *AddressBook
	Internal                *ProtoInternal
	External                *ProtoInternal
	PublicFolderInformation *PublicFolderInformation
}

// ProtoInternal strucuture for unmarshal
type ProtoInternal struct {
	OWAUrl   string
	Protocol *Protocol
}

// MailStore structure for unmarshal
type MailStore struct {
	InternalUrl string
	ExternalUrl string
}

// AddressBook structure for unmarshal
type AddressBook struct {
	InternalUrl string
	ExternalUrl string
}

// PublicFolderInformation structure for unmarshal
type PublicFolderInformation struct {
	SMTPAddress string
}

// Unmarshal returns the XML response as golang structs
func (autodiscresp *AutodiscoverResp) Unmarshal(resp []byte) error {
	//var autodiscresp *AutodiscoverResp
	err := xml.Unmarshal(resp, autodiscresp)
	if err != nil {
		return err //fmt.Printf("error: %v", err)
		//return nil
	}
	return nil
}

// Unmarshal returns the XML response as golang structs
func (autodiscresp *AutodiscoverResp) Marshal() (resp []byte, err error) {
	//var autodiscresp *AutodiscoverResp
	resp, err = xml.Marshal(autodiscresp)
	return resp, err
}
