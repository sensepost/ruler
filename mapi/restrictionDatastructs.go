package mapi

import "github.com/sensepost/ruler/utils"

//Contains the datastructs used to form restrictions

// match types for fuzzy low
const (
	FLFULLSTRING = 0x0000 //field and the value of the column property tag match one another in their entirety
	FLSUBSTRING  = 0x0001 //field matches some portion of the value of the column tag
	FLPREFIX     = 0x0002 //field matches a starting portion of the value of the column tag
)

// match types for fuzzy high
const (
	FLIGNORECASE    = 0x0001 //The comparison does not consider case
	FLIGNOREONSPACE = 0x0002 //The comparison ignores Unicode-defined nonspacing characters such as diacritical marks
	FLLOOSE         = 0x0004 //The comparison results in a match whenever possible, ignoring case and nonspacing characters
)

// search flags
const (
	STOPSEARCH              = 0x00000001
	RESTARTSEARCH           = 0x00000002
	RECURSIVESEARCH         = 0x00000004
	SHALLOWSEARCH           = 0x00000008
	CONTENTINDEXEDSEARCH    = 0x00010000
	NONCONTENTINDEXEDSEARCH = 0x00020000
	STATICSEARCH            = 0x00040000
)

// search return flags
const (
	SEARCHRUNNING     = 0x00000001
	SEARCHREBUILD     = 0x00000002
	SEARCHRECURSIVE   = 0x00000004
	SEARCHCOMPLETE    = 0x00001000
	SEARCHPARTIAL     = 0x00002000
	SEARCHSTATIC      = 0x00010000
	SEARCHMAYBESTATIC = 0x00020000
	CITOTALLY         = 0x01000000
	TWIRTOTALLY       = 0x08000000
)

// Restriction interface to generalise restrictions
type Restriction interface {
	Marshal() []byte
}

// ContentRestriction describes a content restriction,
// which is used to limit a table view to only those rows that include a column
// with contents matching a search string.
type ContentRestriction struct {
	RestrictType   uint8  //0x03
	FuzzyLevelLow  uint16 //type of match
	FuzzyLevelHigh uint16
	PropertyTag    PropertyTag //indicates the propertytag value field
	PropertyValue  TaggedPropertyValue
}

// AndRestriction structure describes a combination of nested conditions that need to be
// AND'ed with each other
type AndRestriction struct {
	RestrictType  uint8 //0x00
	RestrictCount uint16
	Restricts     []Restriction
}

// OrRestriction structure describes a combination of nested conditions that need to be
// OR'ed with each other
type OrRestriction struct {
	RestrictType  uint8 //0x01
	RestrictCount uint16
	Restricts     []Restriction
}

// NotRestriction is used to apply a logical NOT operation to a single restriction
type NotRestriction struct {
	RestrictType uint8 //0x02
	Restriction  Restriction
}

// PropertyRestriction is used to apply a logical NOT operation to a single restriction
type PropertyRestriction struct {
	RestrictType uint8 //0x04
	RelOp        uint8
	PropTag      PropertyTag
	TaggedValue  TaggedPropertyValue
}

// Marshal turn ContentRestriction into Bytes
func (restriction ContentRestriction) Marshal() []byte {
	return utils.BodyToBytes(restriction)
}

// Marshal turn AndResetriction into Bytes
func (restriction AndRestriction) Marshal() []byte {
	return utils.BodyToBytes(restriction)
}

// Marshal turn OrResetriction into Bytes
func (restriction OrRestriction) Marshal() []byte {
	return utils.BodyToBytes(restriction)
}

// Marshal turn NotRestriction into Bytes
func (restriction NotRestriction) Marshal() []byte {
	return utils.BodyToBytes(restriction)
}

// Marshal turn PropertyRestriction into Bytes
func (restriction PropertyRestriction) Marshal() []byte {
	return utils.BodyToBytes(restriction)
}
