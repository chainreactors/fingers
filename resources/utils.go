package resources

import (
	"bytes"
	"encoding/json"
	"github.com/chainreactors/utils/encode"
)

func UnmarshalData(data []byte, v interface{}) error {
	var err error
	if bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
		data, err = encode.GzipDecompress(data)
		if err != nil {
			return nil
		}
	}

	return json.Unmarshal(data, &v)
}
