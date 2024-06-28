package common

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
)

func ParseContent(content []byte) (*http.Response, error) {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(content)), nil)
	if err != nil {
		return nil, nil
	}

	return resp, nil
}

func SplitContent(content []byte) ([]byte, []byte, bool) {
	cs := bytes.Index(content, []byte("\r\n\r\n"))
	if cs != -1 && len(content) >= cs+4 {
		body := content[cs+4:]
		header := content[:cs]
		return header, body, true
	}
	return nil, nil, false
}

func ReadRaw(resp *http.Response) []byte {
	var raw string

	raw += fmt.Sprintf("%s %s\r\n", resp.Proto, resp.Status)
	for k, v := range resp.Header {
		for _, i := range v {
			raw += fmt.Sprintf("%s: %s\r\n", k, i)
		}
	}
	raw += "\r\n"
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte(raw)
	}
	raw += string(body)
	_ = resp.Body.Close()
	return []byte(raw)
}
