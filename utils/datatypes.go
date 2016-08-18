package utils

import "encoding/xml"

//Config containing the session variables
type Config struct {
	Domain   string
	User     string
	Pass     string
	Email    string
	Basic    bool
	Insecure bool
}

//AutodiscoverResp structure for unmarshal
type AutodiscoverResp struct {
	Response Response
}

//Response structure for unmarshal
type Response struct {
	User    User
	Account Account
	Error   AutoError
}

//AutoError structure for unmarshal
type AutoError struct {
	ErrorCode string
	Message   string
	DebugData string
}

//User structure for unmarshal
type User struct {
	DisplayName             string
	LegacyDN                string
	DeploymentID            string
	AutoDiscoverSMTPAddress string
}

//Account structure for unmarshal
type Account struct {
	AccountType     string
	Action          string
	RedirectAddr    string
	MicrosoftOnline bool
	Protocol        []Protocol
}

//Protocol structure for unmarshal
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
	EwsUrl                  string
	EmwsUrl                 string
	SharingUrl              string
	EcpUrl                  string
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
	MailStore               MailStore
	AddressBook             AddressBook
	Internal                ProtoInternal
	External                ProtoInternal
	PublicFolderInformation PublicFolderInformation
}

//ProtoInternal strucuture for unmarshal
type ProtoInternal struct {
	OWAUrl   string
	Protocol *Protocol
}

//MailStore structure for unmarshal
type MailStore struct {
	InternalUrl string
	ExternalUrl string
}

//AddressBook structure for unmarshal
type AddressBook struct {
	Internal string
	External string
}

//PublicFolderInformation structure for unmarshal
type PublicFolderInformation struct {
	SMTPAddress string
}

//UnMarshalResponse returns the XML response as golang structs
func (autodiscresp *AutodiscoverResp) Unmarshal(resp []byte) error {
	//var autodiscresp *AutodiscoverResp
	err := xml.Unmarshal(resp, autodiscresp)
	if err != nil {
		return err //fmt.Printf("error: %v", err)
		//return nil
	}
	return nil
}
