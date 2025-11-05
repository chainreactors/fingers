package alias

import (
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/resources"
	"github.com/chainreactors/utils/iutils"
	"gopkg.in/yaml.v3"
	"strings"
)

func NewAliases(origin ...*Alias) (*Aliases, error) {
	var aliases []*Alias
	err := yaml.Unmarshal(resources.AliasesData, &aliases)
	if err != nil {
		return nil, err
	}
	aliasMap := &Aliases{
		Aliases: make(map[string]*Alias, len(aliases)+len(origin)),
		Map:     make(map[string]map[string]string),
	}

	err = aliasMap.Compile(append(origin, aliases...)) // yaml的优先级高于origin
	if err != nil {
		return nil, err
	}
	return aliasMap, nil
}

type Aliases struct {
	Aliases map[string]*Alias
	Map     map[string]map[string]string // 加速查询的映射表
}

func (as *Aliases) AppendAliases(other []*Alias) {
	for _, alias := range other {
		as.Append(alias)
	}
}

func (as *Aliases) Compile(aliases []*Alias) error {
	for _, alias := range aliases {
		alias.Compile()
		as.Append(alias)
	}
	return nil
}

func (as *Aliases) Append(alias *Alias) {
	// 保留已存在 alias 的 Pocs
	if original, exists := as.Aliases[alias.Name]; exists {
		alias.Pocs = iutils.StringsUnique(append(original.Pocs, alias.Pocs...))
	}

	as.Aliases[alias.Name] = alias

	// 生成映射表
	for engine, engineMap := range alias.AliasMap {
		if _, ok := as.Map[engine]; !ok {
			as.Map[engine] = make(map[string]string)
		}
		for _, name := range engineMap {
			as.Map[engine][resources.NormalizeString(name)] = alias.Name
		}
	}
}

func (as *Aliases) Find(engine, name string) (*Alias, bool) {
	if engineMap, ok := as.Map[engine]; ok {
		if aliasName, ok := engineMap[name]; ok {
			if alias, ok := as.Aliases[aliasName]; ok {
				if !alias.blocked[engine] {
					return alias, true
				}
				return alias, false
			}
		}
	}
	return nil, false
}

func (as *Aliases) FindAny(name string) (string, *Alias, bool) {
	name = resources.NormalizeString(name)
	for engine, _ := range as.Map {
		alias, ok := as.Find(engine, name)
		if ok {
			return engine, alias, ok
		}
	}
	return "", nil, false
}

func (as *Aliases) FindFramework(frame *common.Framework) (*Alias, bool) {
	return as.Find(frame.From.String(), resources.NormalizeString(frame.Name))
}

type Alias struct {
	Name              string `json:"name" yaml:"name" jsonschema:"required,title=Alias Name,description=Unique identifier for the alias,example=nginx"`
	normalizedName    string
	common.Attributes `yaml:",inline" json:",inline"`
	Categories        string              `json:"categories,omitempty" yaml:"categories" jsonschema:"title=Categories,description=Comma-separated labels for categorization,example=web,server,proxy"`
	Priority          int                 `json:"priority,omitempty" yaml:"priority" jsonschema:"title=Priority,description=Priority level (0-5),minimum=0,maximum=5,default=0,example=1"`
	Link              []string            `json:"link,omitempty" yaml:"link" jsonschema:"title=Alias,description=Test target URLs or addresses for validation,example=https://example.com,example=192.168.1.1:8080"`
	AliasMap          map[string][]string `json:"alias" yaml:"alias" jsonschema:"required,title=Alias Map,description=Mapping of engine names to their alias strings"`
	Block             []string            `json:"block,omitempty" yaml:"block" jsonschema:"title=Block List,description=List of engines to block this alias from"`
	blocked           map[string]bool
	Pocs              []string `json:"pocs,omitempty" yaml:"pocs,omitempty" jsonschema:"title=POCs,description=List of POC identifiers associated with this alias"`
}

func (a *Alias) Compile() {
	a.Name = strings.ToLower(a.Name)
	a.normalizedName = resources.NormalizeString(a.Name)
	a.blocked = make(map[string]bool)
	for _, block := range a.Block {
		a.blocked[block] = true
	}
}

func (a *Alias) IsBlocked(key string) bool {
	return a.blocked[key]
}

func (a *Alias) FuzzyMatch(s string) bool {
	return a.normalizedName == resources.NormalizeString(s)
}

func (a *Alias) ToWFN() *common.Attributes {
	a.Part = "a"
	return &a.Attributes
}
