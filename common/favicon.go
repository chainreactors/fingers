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
	if engine.Md5Fingers[md5] != "" {
		return NewFramework(engine.Md5Fingers[md5], FrameFromICO)
	}

	if engine.Mmh3Fingers[mmh3] != "" {
		return NewFramework(engine.Mmh3Fingers[mmh3], FrameFromICO)
	}
	return nil
}

func (engine *Favicons) HashContentMatch(content []byte) *Framework {
	md5h := encode.Md5Hash(content)
	mmh3h := encode.Mmh3Hash32(content)
	return engine.HashMatch(md5h, mmh3h)
}
