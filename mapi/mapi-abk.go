package mapi

import (
	"fmt"

	"github.com/sensepost/ruler/utils"
)

//ExtractMapiAddressBookURL extract the External mapi url from the autodiscover response
func ExtractMapiAddressBookURL(resp *utils.AutodiscoverResp) string {
	for _, v := range resp.Response.Account.Protocol {
		if v.TypeAttr == "mapiHttp" {
			return v.AddressBook.ExternalUrl
		}
	}
	return ""
}

//Bind function to bind to the AddressBook provider
func Bind() (*BindResponse, error) {

	bindReq := BindRequest{}
	bindReq.Flags = 0x00
	bindReq.HasState = 0xFF
	bindReq.State = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE4, 0x04, 0x00, 0x00, 0x09, 0x04, 0x00, 0x00, 0x09, 0x08, 0x00, 0x00}
	bindReq.AuxiliaryBufferSize = 0x00

	if AuthSession.Transport == HTTP {
		resp, responseBody := mapiRequestHTTP(AuthSession.ABKURL.String(), "BIND", bindReq.Marshal())
		responseBody, err := readResponse(resp.Header, responseBody)
		if err != nil {
			return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
		}
		bindResp := BindResponse{}
		_, err = bindResp.Unmarshal(responseBody)
		if err != nil {
			return nil, err
		}
		return &bindResp, nil
	}
	return nil, fmt.Errorf("[x] unexpected error occurred")
}

//GetSpecialTable function to get special table from addressbook provider
func GetSpecialTable() (*GetSpecialTableResponse, error) {

	gstReq := GetSpecialTableRequest{}
	gstReq.Flags = 0x00000004
	gstReq.HasState = 0xFF
	gstReq.State = []byte{0x00, 0x00, 0x00, 0x00, 0x10, 0xC9, 0x63, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE4, 0x04, 0x00, 0x00, 0x09, 0x04, 0x00, 0x00, 0x09, 0x08, 0x00, 0x00}
	gstReq.HasVersion = 0xFF
	gstReq.Version = 0x00
	gstReq.AuxiliaryBufferSize = 0x00

	if AuthSession.Transport == HTTP {
		resp, responseBody := mapiRequestHTTP(AuthSession.ABKURL.String(), "GetSpecialTable", gstReq.Marshal())
		responseBody, err := readResponse(resp.Header, responseBody)
		if err != nil {
			return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
		}
		gstResp := GetSpecialTableResponse{}
		_, err = gstResp.Unmarshal(responseBody)
		if err != nil {
			return nil, err
		}
		return &gstResp, nil
	}
	return nil, fmt.Errorf("[x] unexpected error occurred")
}

//DnToMinID function to map DNs to a set of Minimal Entry IDs
func DnToMinID() (*DnToMinIDResponse, error) {
	//byte[] arrOutput = { 0x2F, 0x4F, 0x3D, 0x45, 0x56, 0x49, 0x4C, 0x43, 0x4F, 0x52, 0x50, 0x00};
	dntominid := DnToMinIDRequest{}
	dntominid.Reserved = 0x00
	dntominid.HasNames = 0xFF
	dntominid.NameCount = 1
	dntominid.NameValues = []byte{0x2F, 0x4F, 0x3D, 0x45, 0x56, 0x49, 0x4C, 0x43, 0x4F, 0x52, 0x50, 0x00}
	if AuthSession.Transport == HTTP {
		resp, responseBody := mapiRequestHTTP(AuthSession.ABKURL.String(), "DNToMId", dntominid.Marshal())
		responseBody, err := readResponse(resp.Header, responseBody)
		if err != nil {
			fmt.Println(err)
			return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
		}
		gstResp := DnToMinIDResponse{}
		_, err = gstResp.Unmarshal(responseBody)
		if err != nil {
			return nil, err
		}
		return &gstResp, nil
	}
	return nil, fmt.Errorf("[x] unexpected error occurred")
}

//GetProps function to get specific properties on an object
func GetProps() {
	isAuthenticated() //check if we actually have a session

	if AuthSession.Transport == HTTP {
		resp, rbody := mapiRequestHTTP(AuthSession.ABKURL.String(), "GetProps", []byte{})
		fmt.Println(resp)
		fmt.Println(string(rbody))
		fmt.Println(AuthSession.CookieJar)
	}
}

//QueryRows function gets number of rows from the specified explicit table
func QueryRows(rowCount int) (*QueryRowsResponse, error) {

	qRows := QueryRowsRequest{}
	qRows.Flags = 0x00
	qRows.HasState = 0xFF
	qRows.State = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xE4, 0x04, 0x00, 0x00, 0x09, 0x04, 0x00, 0x00, 0x09, 0x08, 0x00, 0x00}
	qRows.ExplicitTableCount = 0x00
	qRows.RowCount = uint32(rowCount)
	qRows.HasColumns = 0xFF
	//[]byte{0x1F, 0x00, 0x01, 0x30, 0x1F, 0x00, 0x17, 0x3A, 0x1F, 0x00, 0x08, 0x3A, 0x1F, 0x00, 0x19, 0x3A, 0x1F, 0x00, 0x18, 0x3A, 0x1F, 0x00, 0xFE, 0x39, 0x1F, 0x00, 0x16, 0x3A, 0x1F, 0x00, 0x00, 0x3A, 0x1F, 0x00, 0x02, 0x30, 0x02, 0x01, 0xFF, 0x0F, 0x03, 0x00, 0xFE, 0x0F, 0x03, 0x00, 0x00, 0x39, 0x03, 0x00, 0x05, 0x39, 0x02, 0x01, 0xF6, 0x0F, 0x1F, 0x00, 0x03, 0x30}
	qRows.Columns = LargePropertyTagArray{}
	qRows.Columns.PropertyTagCount = 2
	qRows.Columns.PropertyTags = make([]PropertyTag, qRows.Columns.PropertyTagCount)
	qRows.Columns.PropertyTags[0] = PidTagSMTPAddress
	qRows.Columns.PropertyTags[1] = PidTagDisplayName

	qRows.AuxiliaryBufferSize = 0x00

	if AuthSession.Transport == HTTP {
		resp, responseBody := mapiRequestHTTP(AuthSession.ABKURL.String(), "QueryRows", qRows.Marshal())

		responseBody, err := readResponse(resp.Header, responseBody)

		if err != nil {
			return nil, fmt.Errorf("[x] A HTTP server side error occurred.\n %s", err)
		}
		qrResp := QueryRowsResponse{}
		_, err = qrResp.Unmarshal(responseBody)
		if err != nil {
			return nil, err
		}
		return &qrResp, nil
	}
	return nil, fmt.Errorf("[x] An Unexpected error occurred")
}
