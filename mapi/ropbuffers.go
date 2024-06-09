package mapi

// UnmarshalRops is a wrapper function to keep track of unmarshaling logic and location in our buffer
// takes an array of the expected responses and unmarshals into each one. Returning the first error that occurs,
// or nil if no error
func UnmarshalRops(resp []byte, rops []RopResponse) (bufPtr int, err error) {
	p := 0

	for i := range rops {
		p, err = rops[i].Unmarshal(resp[bufPtr:])
		if err != nil {
			return -1, err
		}
		bufPtr += p
	}

	return
}

// UnmarshalPropertyRops is a wrapper function to keep track of unmarshaling logic and location in our buffer
// takes an array of the expected responses and the columns these have, and unmarshals into each one. Returning the first error that occurs,
// or nil if no error
func UnmarshalPropertyRops(resp []byte, rops []GetProperties, columns []PropertyTag) (bufPtr int, err error) {
	p := 0

	for i := range rops {
		p, err = rops[i].Unmarshal(resp[bufPtr:], columns)
		if err != nil {
			return -1, err
		}
		bufPtr += p
	}

	return
}
