package common

import "github.com/chainreactors/utils/encode"

func NewFavicons() *Favicons {
	return &Favicons{
		Md5Fingers:  make(map[string]string),
		Mmh3Fingers: make(map[string]string),
	}
}

type Favicons struct {
	Md5Fingers  map[string]string
	Mmh3Fingers map[string]string
}

func (engine *Favicons) HashMatch(md5, mmh3 string) *Framework {
	var frame *Framework
	if engine.Md5Fingers[md5] != "" {
		frame = &Framework{Name: engine.Md5Fingers[md5], From: FrameFromICO}
		return frame
	}

	if engine.Mmh3Fingers[mmh3] != "" {
		frame = &Framework{Name: engine.Mmh3Fingers[mmh3], From: FrameFromICO}
		return frame
	}
	return nil
}

func (engine *Favicons) HashContentMatch(content []byte) *Framework {
	md5h := encode.Md5Hash(content)
	mmh3h := encode.Mmh3Hash32(content)
	return engine.HashMatch(md5h, mmh3h)
}
