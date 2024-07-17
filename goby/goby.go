package goby

import (
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/resources"
	"github.com/chainreactors/logs"
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"strings"
)

func NewGobyEngine() (*GobyEngine, error) {
	var fingers []*GobyFinger
	err := resources.UnmarshalData(resources.GobyData, &fingers)
	if err != nil {
		return nil, err
	}
	engine := &GobyEngine{
		Fingers: fingers,
	}
	err = engine.Compile()
	if err != nil {
		return nil, err
	}
	return engine, nil
}

type GobyEngine struct {
	Fingers []*GobyFinger
}

func (engine *GobyEngine) Name() string {
	return "goby"
}

func (engine *GobyEngine) Len() int {
	return len(engine.Fingers)
}

func (engine *GobyEngine) Compile() error {
	for _, finger := range engine.Fingers {
		err := finger.Compile()
		if err != nil {
			return err
		}
	}
	return nil
}

func (engine *GobyEngine) Match(content []byte) common.Frameworks {
	return engine.MatchRaw(string(content))
}

func (engine *GobyEngine) MatchRaw(raw string) common.Frameworks {
	frames := make(common.Frameworks)
	for _, finger := range engine.Fingers {
		frame := finger.Match(raw)
		if frame != nil {
			frames.Add(frame)
		}
	}
	return frames
}

type gobyRule struct {
	Label   string `json:"label"`
	Feature string `json:"feature"`
	IsEquel bool   `json:"is_equal"` //是则判断条件相等，否则判断不等
}

type GobyFinger struct {
	Logic     string `json:"logic"`
	logicExpr *vm.Program
	Name      string     `json:"name"`
	Rule      []gobyRule `json:"rule"`
}

func (finger *GobyFinger) Compile() error {
	for _, r := range finger.Rule {
		r.Feature = strings.ToLower(r.Feature)
	}
	program, err := expr.Compile(finger.Logic)
	if err != nil {
		return err
	}
	finger.logicExpr = program
	return nil
}

func (finger *GobyFinger) Match(raw string) *common.Framework {
	env := map[string]interface{}{}
	for _, r := range finger.Rule {
		if strings.Contains(raw, r.Feature) {
			if r.IsEquel {
				env[r.Label] = true
			} else {
				env[r.Label] = false
			}
		} else {
			if r.IsEquel {
				env[r.Label] = false
			} else {
				env[r.Label] = true
			}
		}
	}
	output, err := expr.Run(finger.logicExpr, env)
	if err != nil {
		logs.Log.Debugf("goby expr error: %v", err)
		return nil
	}

	if output == true {
		return common.NewFramework(finger.Name, common.FrameFromGoby)
	}
	return nil
}
