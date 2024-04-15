package fingers

const (
	None = iota
	ACTIVE
	ICO
	NOTFOUND
	GUESS
)

const (
	INFO int = iota + 1
	MEDIUM
	HIGH
	CRITICAL
)

type Sender func([]byte) ([]byte, bool)

type senddata []byte

func (d senddata) IsNull() bool {
	if len(d) == 0 {
		return true
	}
	return false
}
