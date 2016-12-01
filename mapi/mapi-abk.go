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

//BindAddressBook function to bind to the AddressBook provider
func BindAddressBook() (*BindResponse, error) {

	bindReq := BindRequest{}
	bindReq.Flags = 0x00
	bindReq.HasState = 0xFF
	bindReq.State = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE4, 0x04, 0x00, 0x00, 0x09, 0x04, 0x00, 0x00, 0x09, 0x08, 0x00, 0x00}
	bindReq.AuxiliaryBufferSize = 0x00

	if AuthSession.Transport == HTTP {
		responseBody, err := mapiRequestHTTP(AuthSession.ABKURL.String(), "BIND", bindReq.Marshal())

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
		responseBody, err := mapiRequestHTTP(AuthSession.ABKURL.String(), "GetSpecialTable", gstReq.Marshal())

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
		responseBody, err := mapiRequestHTTP(AuthSession.ABKURL.String(), "DNToMId", dntominid.Marshal())

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
		resp, _ := mapiRequestHTTP(AuthSession.ABKURL.String(), "GetProps", []byte{})
		fmt.Println(resp)
		//fmt.Println(string(rbody))
		fmt.Println(AuthSession.CookieJar)
	}
}

//QueryRows function gets number of rows from the specified explicit table
func QueryRows(rowCount int, columns []PropertyTag) (*QueryRowsResponse, error) {

	qRows := QueryRowsRequest{}
	qRows.Flags = 0x00
	qRows.HasState = 0xFF
	qRows.State = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xE4, 0x04, 0x00, 0x00, 0x09, 0x04, 0x00, 0x00, 0x09, 0x08, 0x00, 0x00}
	qRows.ExplicitTableCount = 0x00
	qRows.RowCount = uint32(rowCount)
	qRows.HasColumns = 0xFF

	qRows.Columns = LargePropertyTagArray{}
	qRows.Columns.PropertyTagCount = uint32(len(columns))
	qRows.Columns.PropertyTags = columns //

	qRows.AuxiliaryBufferSize = 0x00

	if AuthSession.Transport == HTTP {
		responseBody, err := mapiRequestHTTP(AuthSession.ABKURL.String(), "QueryRows", qRows.Marshal())

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
