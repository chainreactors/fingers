package common

import (
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
)

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
	Part      string `json:"part,omitempty" yaml:"part" jsonschema:"nullable,title=Part,description=Component part identifier"`
	Vendor    string `json:"vendor,omitempty" yaml:"vendor" jsonschema:"nullable,title=Vendor,description=Vendor or manufacturer name"`
	Product   string `json:"product,omitempty" yaml:"product" jsonschema:"nullable,title=Product,description=Product name"`
	Version   string `json:"version,omitempty" yaml:"version,omitempty" jsonschema:"nullable,title=Version,description=Product version"`
	Update    string `json:"update,omitempty" yaml:"update,omitempty" jsonschema:"nullable,title=Update,description=Product update version"`
	Edition   string `json:"edition,omitempty" yaml:"edition,omitempty" jsonschema:"nullable,title=Edition,description=Product edition"`
	SWEdition string `json:"sw_edition,omitempty" yaml:"sw_edition,omitempty" jsonschema:"nullable,title=Software Edition,description=Software edition"`
	TargetSW  string `json:"target_sw,omitempty" yaml:"target_sw,omitempty" jsonschema:"nullable,title=Target Software,description=Target software"`
	TargetHW  string `json:"target_hw,omitempty" yaml:"target_hw,omitempty" jsonschema:"nullable,title=Target Hardware,description=Target hardware"`
	Other     string `json:"other,omitempty" yaml:"other,omitempty" jsonschema:"nullable,title=Other,description=Other attributes"`
	Language  string `json:"language,omitempty" yaml:"language,omitempty" jsonschema:"nullable,title=Language,description=Language identifier"`
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

// ParseCPEKey extracts vendor and product from a CPE string.
// Supported formats:
//   - "vendor:product"                          (shorthand)
//   - "cpe:2.3:a:vendor:product:*:..."          (CPE 2.3 formatted string)
//   - "cpe:/a:vendor:product:..."               (CPE 2.2 URI)
func ParseCPEKey(raw string) (vendor, product string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}

	if strings.HasPrefix(raw, "cpe:/") || strings.HasPrefix(raw, "cpe:2.3:") {
		attr := NewAttributesWithCPE(raw)
		if attr == nil {
			return "", ""
		}
		vendor = strings.ToLower(strings.TrimSpace(attr.Vendor))
		product = strings.ToLower(strings.TrimSpace(attr.Product))
		if vendor == "" || vendor == "*" || product == "" || product == "*" {
			return "", ""
		}
		return vendor, product
	}

	if idx := strings.IndexByte(raw, ':'); idx > 0 && idx < len(raw)-1 {
		vendor = strings.ToLower(strings.TrimSpace(raw[:idx]))
		product = strings.ToLower(strings.TrimSpace(raw[idx+1:]))
		if vendor != "" && product != "" {
			return vendor, product
		}
	}

	return "", ""
}

// CPEKey joins vendor and product into the canonical "vendor:product" key.
func CPEKey(vendor, product string) string {
	return strings.ToLower(vendor) + ":" + strings.ToLower(product)
}
