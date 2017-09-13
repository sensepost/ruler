package mapi

type ropid uint8

const (
	RopReserved ropid = 0x00
	RopRelease  ropid = 0x01
	RopOpenFolder
	RopOpenMessage
	RopGetHierarchyTable
	RopGetContentsTable
	RopCreateMessage
	RopGetPropertiesSpecific
)
