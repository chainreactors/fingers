package common

import "github.com/facebookincubator/nvdtools/wfn"

func NewAttributesWithAny() *Attributes {
	return &Attributes{}
}

func NewAttributesWithCPE(s string) *Attributes {
	attr, err := wfn.Parse(s)
	if err != nil {
		return nil
	}
	return &Attributes{
		Part:      attr.Part,
		Vendor:    attr.Vendor,
		Product:   attr.Product,
		Version:   attr.Version,
		Update:    attr.Update,
		Edition:   attr.Edition,
		SWEdition: attr.SWEdition,
		TargetSW:  attr.TargetSW,
		TargetHW:  attr.TargetHW,
		Other:     attr.Other,
		Language:  attr.Language,
	}
}

type Attributes struct {
	Part      string `json:"part,omitempty" yaml:"part" jsonschema:"title=Part,description=Component part identifier"`
	Vendor    string `json:"vendor,omitempty" yaml:"vendor" jsonschema:"title=Vendor,description=Vendor or manufacturer name"`
	Product   string `json:"product,omitempty" yaml:"product" jsonschema:"title=Product,description=Product name"`
	Version   string `json:"version,omitempty" yaml:"version,omitempty" jsonschema:"title=Version,description=Product version"`
	Update    string `json:"update,omitempty" yaml:"update,omitempty" jsonschema:"title=Update,description=Product update version"`
	Edition   string `json:"edition,omitempty" yaml:"edition,omitempty" jsonschema:"title=Edition,description=Product edition"`
	SWEdition string `json:"sw_edition,omitempty" yaml:"sw_edition,omitempty" jsonschema:"title=Software Edition,description=Software edition"`
	TargetSW  string `json:"target_sw,omitempty" yaml:"target_sw,omitempty" jsonschema:"title=Target Software,description=Target software"`
	TargetHW  string `json:"target_hw,omitempty" yaml:"target_hw,omitempty" jsonschema:"title=Target Hardware,description=Target hardware"`
	Other     string `json:"other,omitempty" yaml:"other,omitempty" jsonschema:"title=Other,description=Other attributes"`
	Language  string `json:"language,omitempty" yaml:"language,omitempty" jsonschema:"title=Language,description=Language identifier"`
}

func (a *Attributes) WFN() *wfn.Attributes {
	return &wfn.Attributes{
		Part:      a.Part,
		Vendor:    a.Vendor,
		Product:   a.Product,
		Version:   a.Version,
		Update:    a.Update,
		Edition:   a.Edition,
		SWEdition: a.SWEdition,
		TargetSW:  a.TargetSW,
		TargetHW:  a.TargetHW,
		Other:     a.Other,
	}
}

func (a *Attributes) URI() string {
	return a.WFN().BindToURI()
}

func (a *Attributes) String() string {
	return a.WFN().BindToFmtString()
}

func (a *Attributes) WFNString() string {
	return a.WFN().String()
}
