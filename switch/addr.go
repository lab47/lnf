package ethswitch

const hexDigit = "0123456789abcdef"

type HardwareAddr [6]byte

func (a HardwareAddr) String() string {
	buf := make([]byte, 0, (6*2)+5)
	for i, b := range a {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hexDigit[b>>4])
		buf = append(buf, hexDigit[b&0xF])
	}
	return string(buf)
}
