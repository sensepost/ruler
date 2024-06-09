package mapi

import (
	"fmt"

	rpchttp "github.com/sensepost/ruler/rpc-http"
	"github.com/sensepost/ruler/utils"
)

func sendAddressBookRequest(mapiType string, mapi []byte) ([]byte, error) {
	if AuthSession.Transport == HTTP {
		return mapiRequestHTTP(AuthSession.ABKURL.String(), mapiType, mapi)
	}

	//return rpchttp.EcDoRPCExt2(mapi, 0)
	return rpchttp.EcDoRPCAbk(mapi, 0)
	//return nil, nil
}

// ExtractMapiAddressBookURL extract the External mapi url from the autodiscover response
func ExtractMapiAddressBookURL(resp *utils.AutodiscoverResp) string {
	for _, v := range resp.Response.Account.Protocol {
		if v.TypeAttr == "mapiHttp" {
			return v.AddressBook.ExternalUrl
		}
	}
	return ""
}

// BindAddressBook function to bind to the AddressBook provider
func BindAddressBook() (*BindResponse, error) {

	bindReq := BindRequest{}
	bindReq.Flags = 0x00
	bindReq.HasState = 0xFF
	bindReq.State = STAT{0x00, 0x00, 0x00, 0x00, 0x00, 0xFFFFFFFF, 1252, 1033, 2057}.Marshal()
	bindReq.AuxiliaryBufferSize = 0x00

	responseBody, err := sendAddressBookRequest("BIND", bindReq.Marshal())

	if err != nil {
		return nil, fmt.Errorf("A HTTP server side error occurred.\n %s", err)
	}

	bindResp := BindResponse{}
	_, err = bindResp.Unmarshal(responseBody)
	if err != nil {
		return nil, err
	}
	return &bindResp, nil

	//return nil, fmt.Errorf("unexpected error occurred")
}

// BindAddressBookRPC function to bind to the AddressBook provider
func BindAddressBookRPC() (*BindResponse, error) {

	bindReq := BindRequestRPC{}
	bindReq.Flags = 0x00
	bindReq.State = STAT{0x00, 0x00, 0x00, 0x00, 0x00, 0xFFFFFFFF, 1252, 1033, 2057}.Marshal()
	bindReq.ServerGUID = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x10, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x1f, 0x00, 0x01, 0x30, 0x1f, 0x00, 0x17, 0x3a, 0x1f, 0x00, 0x08, 0x3a, 0x1f, 0x00, 0x19, 0x3a, 0x1f, 0x00, 0x18, 0x3a, 0x1f, 0x00, 0xfe, 0x39, 0x1f, 0x00, 0x16, 0x3a, 0x1f, 0x00, 0x00, 0x3a, 0x1f, 0x00, 0x02, 0x30, 0x02, 0x01, 0xff, 0x0f, 0x03, 0x00, 0xfe, 0x0f, 0x03, 0x00, 0x00, 0x39, 0x03, 0x00, 0x05, 0x39}

	data := bindReq.Marshal()
	responseBody, err := rpchttp.EcDoRPCAbk(data, len(bindReq.ServerGUID)-10)

	if err != nil {
		return nil, fmt.Errorf("A HTTP server side error occurred.\n %s", err)
	}

	bindResp := BindResponse{}
	_, err = bindResp.Unmarshal(responseBody)
	if err != nil {
		return nil, err
	}
	return &bindResp, nil

	//return nil, fmt.Errorf("unexpected error occurred")
}

// GetSpecialTable function to get special table from addressbook provider
func GetSpecialTable() (*GetSpecialTableResponse, error) {

	gstReq := GetSpecialTableRequest{}
	gstReq.Flags = 0x00000004
	gstReq.HasState = 0xFF
	gstReq.State = STAT{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 1252, 1033, 2057}.Marshal()
	gstReq.HasVersion = 0xFF
	gstReq.Version = 0x00
	gstReq.AuxiliaryBufferSize = 0x00

	responseBody, err := sendAddressBookRequest("GetSpecialTable", gstReq.Marshal())

	if err != nil {
		return nil, fmt.Errorf("A HTTP server side error occurred.\n %s", err)
	}
	gstResp := GetSpecialTableResponse{}
	_, err = gstResp.Unmarshal(responseBody)
	if err != nil {
		return nil, err
	}
	return &gstResp, nil

}

// DnToMinID function to map DNs to a set of Minimal Entry IDs
func DnToMinID() (*DnToMinIDResponse, error) {
	//byte[] arrOutput = { 0x2F, 0x4F, 0x3D, 0x45, 0x56, 0x49, 0x4C, 0x43, 0x4F, 0x52, 0x50, 0x00};
	dntominid := DnToMinIDRequest{}
	dntominid.Reserved = 0x00
	dntominid.HasNames = 0xFF
	dntominid.NameCount = 1
	dntominid.NameValues = []byte{0x2F, 0x4F, 0x3D, 0x45, 0x56, 0x49, 0x4C, 0x43, 0x4F, 0x52, 0x50, 0x00}

	responseBody, err := sendAddressBookRequest("DNToMId", dntominid.Marshal())

	if err != nil {
		fmt.Println(err)
		return nil, fmt.Errorf("A HTTP server side error occurred.\n %s", err)
	}
	gstResp := DnToMinIDResponse{}
	_, err = gstResp.Unmarshal(responseBody)
	if err != nil {
		return nil, err
	}
	return &gstResp, nil

}

// GetProps function to get specific properties on an object
func GetProps() {
	isAuthenticated() //check if we actually have a session

	resp, _ := sendAddressBookRequest("GetProps", []byte{})
	fmt.Println(resp)
	//fmt.Println(string(rbody))
	fmt.Println(AuthSession.CookieJar)

}

// QueryRows function gets number of rows from the specified explicit table
func QueryRows(rowCount int, state []byte, columns []PropertyTag) (*QueryRowsResponse, error) {

	qRows := QueryRowsRequest{}
	qRows.Flags = 0x00
	qRows.HasState = 0xFF
	if len(state) == 0 {
		state = STAT{0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 1252, 1033, 2057}.Marshal()
	}
	qRows.State = state //
	qRows.ExplicitTableCount = 0x00
	qRows.RowCount = uint32(rowCount)
	qRows.HasColumns = 0xFF

	qRows.Columns = LargePropertyTagArray{}
	qRows.Columns.PropertyTagCount = uint32(len(columns))
	qRows.Columns.PropertyTags = columns //

	qRows.AuxiliaryBufferSize = 0x00

	responseBody, err := sendAddressBookRequest("QueryRows", qRows.Marshal())

	if err != nil {
		return nil, fmt.Errorf("A HTTP server side error occurred.\n %s", err)
	}
	qrResp := QueryRowsResponse{}
	_, err = qrResp.Unmarshal(responseBody)
	if err != nil {
		return nil, err
	}
	return &qrResp, nil

}

// SeekEntries function moves the pointer to a new position in the addressbook
func SeekEntries(entryStart []byte, columns []PropertyTag) (*QueryRowsResponse, error) {

	qRows := SeekEntriesRequest{}
	qRows.HasState = 0xFF
	qRows.State = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xE4, 0x04, 0x00, 0x00, 0x09, 0x04, 0x00, 0x00, 0x09, 0x08, 0x00, 0x00}
	//qRows.HasTarget = 0xFF
	val := []byte{0x00, 0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x0, 0x0, 0x0, 0x08, 0x0, 0x0, 0x0}
	val = append(val, entryStart...)
	qRows.Target = AddressBookTaggedPropertyValue{PropertyType: 0x001F, PropertyID: 0x3001, PropertyValue: val}
	qRows.HasExplicitTable = 0x00
	//qRows.ExplicitTableCount = 0x00
	qRows.HasColumns = 0xFF

	qRows.Columns = LargePropertyTagArray{}
	qRows.Columns.PropertyTagCount = uint32(len(columns))
	qRows.Columns.PropertyTags = columns //

	qRows.AuxiliaryBufferSize = 0x00

	responseBody, err := sendAddressBookRequest("SeekEntries", qRows.Marshal())

	if err != nil {
		return nil, fmt.Errorf("A HTTP server side error occurred.\n %s", err)
	}
	qrResp := QueryRowsResponse{}
	_, err = qrResp.Unmarshal(responseBody)
	if err != nil {
		return nil, err
	}
	return &qrResp, nil

}
