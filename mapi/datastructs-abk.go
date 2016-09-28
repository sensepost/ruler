package mapi

import "fmt"

//BindRequest struct used in bind request to bind to addressbook
type BindRequest struct {
	Flags               uint32
	HasState            byte
	State               []byte //optional 36 bytes
	AuxiliaryBufferSize uint32
	AuxiliaryBuffer     []byte
}

//BindResponse struct
type BindResponse struct {
	StatusCode          uint32
	ErrorCode           uint32
	ServerGUID          []byte
	AuxiliaryBufferSize uint32
	AuxiliaryBuffer     []byte
}

//GetSpecialTableRequest struct used to get list of addressbooks
type GetSpecialTableRequest struct {
	Flags               uint32
	HasState            byte
	State               []byte //optional 36 bytes
	HasVersion          byte
	Version             uint32 //optional if HasVersion
	AuxiliaryBufferSize uint32
	AuxiliaryBuffer     []byte
}

//GetSpecialTableResponse struct
type GetSpecialTableResponse struct {
	StatusCode          uint32
	ErrorCode           uint32
	CodePage            uint32
	HasVersion          byte
	Version             uint32 //if hasversion is set
	HasRows             byte
	RowsCount           uint32 //if HasRows is set
	Rows                []AddressBookPropertyValueList
	AuxiliaryBufferSize uint32
	AuxiliaryBuffer     []byte
}

//DnToMinIDRequest struct used to get list of addressbooks
type DnToMinIDRequest struct {
	Reserved            uint32
	HasNames            byte
	NameCount           uint32
	NameValues          []byte
	AuxiliaryBufferSize uint32
	AuxiliaryBuffer     []byte
}

//DnToMinIDResponse struct
type DnToMinIDResponse struct {
	StatusCode          uint32
	ErrorCode           uint32
	HasMinimalIds       byte
	MinimalIDCount      uint32 //if hasversion is set
	MinimalIds          []byte
	AuxiliaryBufferSize uint32
	AuxiliaryBuffer     []byte
}

//QueryRowsRequest struct used to get list of addressbooks
type QueryRowsRequest struct {
	Flags               uint32
	HasState            byte
	State               []byte //36 bytes if hasstate
	ExplicitTableCount  uint32
	ExplicitTable       []byte //array of MinimalEntryID
	RowCount            uint32
	HasColumns          byte
	Columns             LargePropertyTagArray //array of LargePropertyTagArray if hascolumns is set
	AuxiliaryBufferSize uint32
	AuxiliaryBuffer     []byte
}

//QueryRowsResponse struct
type QueryRowsResponse struct {
	StatusCode          uint32
	ErrorCode           uint32
	HasState            byte
	State               []byte //36 bytes if hasState enabled
	HasColsAndRows      byte
	Columns             []byte //array of LargePropertyTagArray //set if HasColsAndRows is set
	RowCount            uint32 //if HasColsAndRows is non-zero
	RowData             []AddressBookPropertyRow
	AuxiliaryBufferSize uint32
	AuxiliaryBuffer     []byte
}

//AddressBookPropertyValueList used to list addressbook
type AddressBookPropertyValueList struct {
	PropertyValueCount uint32
	PropertyValues     []AddressBookTaggedPropertyValue
}

//AddressBookTaggedPropertyValue used to hold a value for an Addressbook entry
type AddressBookTaggedPropertyValue struct {
	PropertyType  uint16
	PropertyID    uint16
	PropertyValue []byte
}

//AddressBookPropertyRow struct to hold addressbook entries
type AddressBookPropertyRow struct {
	Flags uint8 //if 0x0 -- ValueArray = type(AddressBookPropertyValue)
	//if 0x1 ValueArray = type(AddressBookFlaggedPropertyValueWithType)
	ValueArray []byte
}

//LargePropertyTagArray contains a list of propertytags
type LargePropertyTagArray struct {
	PropertyTagCount uint32
	PropertyTags     []PropertyTag
}

//Marshal turn BindRequest into Bytes
func (bindRequest BindRequest) Marshal() []byte {
	return BodyToBytes(bindRequest)
}

//Marshal turn GetSpecialTableRequest into Bytes
func (specialTableRequest GetSpecialTableRequest) Marshal() []byte {
	return BodyToBytes(specialTableRequest)
}

//Marshal turn DnToMinIDRequest into Bytes
func (dntominid DnToMinIDRequest) Marshal() []byte {
	return BodyToBytes(dntominid)
}

//Marshal turn QueryRowsRequest into Bytes
func (qrows QueryRowsRequest) Marshal() []byte {
	return BodyToBytes(qrows)
}

//Unmarshal func
func (abt *AddressBookPropertyValueList) Unmarshal(resp []byte) (int, error) {
	pos := 0
	abt.PropertyValueCount, pos = readUint32(pos, resp)
	abt.PropertyValues = make([]AddressBookTaggedPropertyValue, int(abt.PropertyValueCount))
	fmt.Printf("Values: %d\n\n", abt.PropertyValueCount)
	for k := 0; k < len(abt.PropertyValues); k++ {
		abt.PropertyValues[k] = AddressBookTaggedPropertyValue{}
		p, _ := abt.PropertyValues[k].Unmarshal(resp[pos:])
		pos += p
	}
	return pos, nil
}

//Unmarshal func for the AddressBookTaggedPropertyValue structure
func (abt *AddressBookTaggedPropertyValue) Unmarshal(resp []byte) (int, error) {
	pos := 0
	abt.PropertyType, pos = readUint16(pos, resp)
	abt.PropertyID, pos = readUint16(pos, resp)

	if abt.PropertyType == PtypInteger32 {
		abt.PropertyValue, pos = readBytes(pos, 4, resp)
	} else if abt.PropertyType == PtypInteger64 {
		abt.PropertyValue, pos = readBytes(pos, 8, resp)
	} else if abt.PropertyType == PtypString {
		t, p := readByte(pos, resp) // check HasValue
		pos = p
		if t == 0xFF { // check if hasValue
			abt.PropertyValue, pos = readUnicodeString(pos, resp)
			pos++
		}
	} else if abt.PropertyType == PtypBoolean {
		abt.PropertyValue, pos = readBytes(pos, 1, resp)
	} else if abt.PropertyType == PtypBinary {
		t, p := readByte(pos, resp) // check HasValue
		pos = p
		if t == 0xFF {
			cnt, p := readUint32(pos, resp) // check cnt
			pos = p
			abt.PropertyValue, pos = readBytes(pos, int(cnt), resp)
		}
	}

	return pos, nil
}

//Unmarshal func
func (bindResponse *BindResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0
	bindResponse.StatusCode, pos = readUint32(pos, resp)
	bindResponse.ErrorCode, pos = readUint32(pos, resp)
	if bindResponse.ErrorCode != 0 {
		return pos, fmt.Errorf("Non-zero return value %d", bindResponse.ErrorCode)
	}
	bindResponse.ServerGUID, pos = readBytes(pos, 16, resp)
	bindResponse.AuxiliaryBufferSize, pos = readUint32(pos, resp)
	if bindResponse.AuxiliaryBufferSize != 0 {
		bindResponse.AuxiliaryBuffer, pos = readBytes(pos, int(bindResponse.AuxiliaryBufferSize), resp)
	}
	return pos, nil
}

//Unmarshal func
func (gstResponse *GetSpecialTableResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0
	gstResponse.StatusCode, pos = readUint32(pos, resp)
	gstResponse.ErrorCode, pos = readUint32(pos, resp)
	if gstResponse.ErrorCode != 0 {
		return pos, fmt.Errorf("Non-zero return value %d", gstResponse.ErrorCode)
	}
	gstResponse.CodePage, pos = readUint32(pos, resp)
	gstResponse.HasVersion, pos = readByte(pos, resp)
	if gstResponse.HasVersion == 0xFF {
		gstResponse.Version, pos = readUint32(pos, resp)
	}
	gstResponse.HasRows, pos = readByte(pos, resp)
	if gstResponse.HasRows == 0xFF {
		gstResponse.RowsCount, pos = readUint32(pos, resp)
		fmt.Println(gstResponse.RowsCount)
		gstResponse.Rows = make([]AddressBookPropertyValueList, gstResponse.RowsCount)
		for k := 0; k < int(gstResponse.RowsCount); k++ {
			gstResponse.Rows[k] = AddressBookPropertyValueList{}
			p, _ := gstResponse.Rows[k].Unmarshal(resp[pos:])
			pos += p
		}
		//gstResponse.Rows,pos = read
	}
	gstResponse.AuxiliaryBufferSize, pos = readUint32(pos, resp)
	if gstResponse.AuxiliaryBufferSize != 0 {
		gstResponse.AuxiliaryBuffer, pos = readBytes(pos, int(gstResponse.AuxiliaryBufferSize), resp)
	}
	return pos, nil
}

//Unmarshal func
func (dnResponse *DnToMinIDResponse) Unmarshal(resp []byte) (int, error) {
	pos := 0
	dnResponse.StatusCode, pos = readUint32(pos, resp)
	dnResponse.ErrorCode, pos = readUint32(pos, resp)
	if dnResponse.ErrorCode != 0 {
		return pos, fmt.Errorf("Non-zero return value %d", dnResponse.ErrorCode)
	}
	if dnResponse.HasMinimalIds == 0xFF {
		dnResponse.MinimalIDCount, pos = readUint32(pos, resp)
		//dnResponse.MinimalIds, pos = read
	}
	dnResponse.AuxiliaryBufferSize, pos = readUint32(pos, resp)
	if dnResponse.AuxiliaryBufferSize != 0 {
		dnResponse.AuxiliaryBuffer, pos = readBytes(pos, int(dnResponse.AuxiliaryBufferSize), resp)
	}
	return pos, nil
}
