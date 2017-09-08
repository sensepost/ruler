package mapi

func UnmarshalRop(resp []byte, rop RopResponse) (int, error) {
	p, err := rop.Unmarshal(resp)
	return p, err
}

//UnmarshalRops is a wrapper function to keep track of unmarshaling logic and location in our buffer
//takes an array of the expected responses and unmarshals into each one. Returning the first error that occurs,
//or nil if no error
func UnmarshalRops(resp []byte, rops []RopResponse) (err error) {
	bufPtr := 0
	p := 0

	for i := range rops {
		p, err = rops[i].Unmarshal(resp[bufPtr:])
		if err != nil {
			return err
		}
		bufPtr += p
	}

	return err
}
