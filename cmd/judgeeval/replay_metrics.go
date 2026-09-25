package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/judge"
)

type detectionScore struct {
	TP int `json:"tp"`
	FP int `json:"fp"`
	TN int `json:"tn"`
	FN int `json:"fn"`
}

func (s *detectionScore) add(want, got bool) {
	switch {
	case want && got:
		s.TP++
	case want:
		s.FN++
	case got:
		s.FP++
	default:
		s.TN++
	}
}

type versionScore struct {
	Correct            int `json:"correct"`
	Wrong              int `json:"wrong"`
	Missing            int `json:"missing"`
	CorrectAbstentions int `json:"correct_abstentions"`
	Unsupported        int `json:"unsupported"`
	ProductMissing     int `json:"product_missing"`
}

func (v *versionScore) add(f *common.Framework, want string) {
	if f == nil {
		v.ProductMissing++
		return
	}
	got := f.Version
	switch {
	case want == "" && got == "":
		v.CorrectAbstentions++
	case want == "":
		v.Unsupported++
	case got == want:
		v.Correct++
	case got == "":
		v.Missing++
	default:
		v.Wrong++
	}
}

type stageScore struct {
	Detection             detectionScore `json:"detection"`
	Versions              versionScore   `json:"versions"`
	UnlabelledPredictions int            `json:"unlabelled_predictions"`
}
type replaySummary struct {
	Model                   string             `json:"model"`
	BaselineSource          string             `json:"baseline_source"`
	Samples                 int                `json:"samples"`
	UniqueHosts             int                `json:"unique_hosts"`
	UniqueResponses         int                `json:"unique_responses"`
	Errors                  int                `json:"errors"`
	LabelledPairs           int                `json:"labelled_pairs"`
	Baseline                stageScore         `json:"baseline"`
	Refined                 stageScore         `json:"refined"`
	Completed               stageScore         `json:"completed"`
	FalseHitsRemoved        int                `json:"false_hits_removed"`
	TrueHitsRemoved         int                `json:"true_hits_removed"`
	NaturalMissesRecovered  int                `json:"natural_misses_recovered"`
	MissedProductsSuggested int                `json:"missed_products_suggested"`
	VersionFills            int                `json:"version_fills"`
	CorrectVersionFills     int                `json:"correct_version_fills"`
	IncorrectVersionFills   int                `json:"incorrect_version_fills"`
	UnlabelledVersionFills  int                `json:"unlabelled_version_fills"`
	Generation              []generationResult `json:"generation"`
	Disagreements           []string           `json:"disagreements"`
	Requests                int                `json:"provider_requests"`
	CacheHits               int                `json:"exact_cache_hits"`
	InputTokens             int64              `json:"input_tokens"`
	Seconds                 float64            `json:"seconds"`
}

func summarizeReplay(m *replayManifest, rows []replayRow, gen []generationResult) replaySummary {
	out := replaySummary{Samples: len(m.Samples), Generation: gen}
	hosts, hashes := map[string]bool{}, map[string]bool{}
	byID := map[string]replayRow{}
	for _, r := range rows {
		byID[r.ID] = r
	}
	for _, s := range m.Samples {
		hosts[s.Group] = true
		hashes[s.ContentSHA256] = true
		r, ok := byID[s.ID]
		if !ok || r.Err != "" {
			out.Errors++
			continue
		}
		for _, stage := range []struct {
			score  *stageScore
			frames common.Frameworks
		}{{&out.Baseline, r.Baseline}, {&out.Refined, r.Refined}, {&out.Completed, r.Completed}} {
			for _, l := range s.Labels {
				f := findLabel(stage.frames, l)
				stage.score.Detection.add(l.Present, f != nil)
				if l.Version != nil {
					stage.score.Versions.add(f, *l.Version)
				}
			}
			for _, f := range stage.frames {
				if f != nil {
					if _, ok := labelFor(s, f.Name); !ok {
						stage.score.UnlabelledPredictions++
					}
				}
			}
		}
		for _, l := range s.Labels {
			out.LabelledPairs++
			before, after := findLabel(r.Baseline, l), findLabel(r.Completed, l)
			if before != nil && after == nil {
				if l.Present {
					out.TrueHitsRemoved++
				} else {
					out.FalseHitsRemoved++
				}
			}
			if l.Present && before == nil && after != nil {
				out.NaturalMissesRecovered++
			}
			if l.Present && after == nil && containsProductName(r.Suggestions, l) {
				out.MissedProductsSuggested++
			}
			// Count a labelled product once, considering all baseline aliases.
			// Raw per-name changes remain in rows.jsonl for audit.
			if after != nil && after.Version != "" && (before == nil || before.Version == "") {
				out.VersionFills++
				switch {
				case !l.Present:
					out.IncorrectVersionFills++
				case l.Version == nil:
					out.UnlabelledVersionFills++
				case after.Version == *l.Version:
					out.CorrectVersionFills++
				default:
					out.IncorrectVersionFills++
				}
			}
			if (after != nil) != l.Present {
				out.Disagreements = append(out.Disagreements, fmt.Sprintf("%s %s: presence want=%t got=%t", s.ID, l.Product, l.Present, after != nil))
			}
			if l.Version != nil && after != nil && after.Version != *l.Version {
				out.Disagreements = append(out.Disagreements, fmt.Sprintf("%s %s: version want=%q got=%q", s.ID, l.Product, *l.Version, after.Version))
			}
		}
		unlabelled := map[string]bool{}
		for name := range r.Filled {
			if _, ok := labelFor(s, name); ok {
				continue
			}
			key := judge.NormalizeName(name)
			if !unlabelled[key] {
				unlabelled[key] = true
				out.VersionFills++
				out.UnlabelledVersionFills++
			}
		}
	}
	out.UniqueHosts = len(hosts)
	out.UniqueResponses = len(hashes)
	return out
}
func containsProductName(names []string, l productLabel) bool {
	for _, name := range names {
		for _, expected := range append([]string{l.Product}, l.Aliases...) {
			if judge.NormalizeName(name) == judge.NormalizeName(expected) {
				return true
			}
		}
	}
	return false
}
func writeReplayReport(path string, s replaySummary) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# 真实响应回放评估\n\n模型：%s；基线：%s。\n\n%d 份快照，%d 个主机组，%d 种去除易变响应头后的响应，%d 个已标注产品判断，失败 %d 份。\n\n", s.Model, s.BaselineSource, s.Samples, s.UniqueHosts, s.UniqueResponses, s.LabelledPairs, s.Errors)
	b.WriteString("统计范围是保存的响应所支持的产品与版本。页面自报版本不是服务器安装审计；正负标注不代表完整技术栈。未标注的输出不计为误报，也不计为已证明正确。页面级结果含同主机响应，不能视作独立随机样本。\n\n")
	b.WriteString("| 阶段 | TP | FP | FN | TN | 未标注输出 |\n|---|---:|---:|---:|---:|---:|\n")
	for _, r := range []struct {
		name string
		s    stageScore
	}{{"原结果", s.Baseline}, {"Refine", s.Refined}, {"逐产品补版本", s.Completed}} {
		d := r.s.Detection
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d |\n", r.name, d.TP, d.FP, d.FN, d.TN, r.s.UnlabelledPredictions)
	}
	fmt.Fprintf(&b, "\n有标注的误报移除 %d；真实命中误删 %d；自然漏报补回 %d。模型拒绝或新增的未标注项保留在 rows.jsonl 中供复核。\n\n", s.FalseHitsRemoved, s.TrueHitsRemoved, s.NaturalMissesRecovered)
	fmt.Fprintf(&b, "仍漏报的产品中，名称建议覆盖 %d 项；建议不计作已识别，也不计作漏报补回。\n\n", s.MissedProductsSuggested)
	b.WriteString("| 版本阶段 | 正确 | 错误 | 缺版本 | 正确留空 | 无依据填值 | 产品未识别 |\n|---|---:|---:|---:|---:|---:|---:|\n")
	for _, r := range []struct {
		name string
		s    versionScore
	}{{"原结果", s.Baseline.Versions}, {"Refine", s.Refined.Versions}, {"逐产品补版本", s.Completed.Versions}} {
		v := r.s
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d | %d |\n", r.name, v.Correct, v.Wrong, v.Missing, v.CorrectAbstentions, v.Unsupported, v.ProductMissing)
	}
	fmt.Fprintf(&b, "\n按产品合并别名后的新增版本 %d：标注确认正确 %d、错误 %d、未标注 %d。已有非空版本保留，错误由报告揭示；逐名称变化见 rows.jsonl。\n\n", s.VersionFills, s.CorrectVersionFills, s.IncorrectVersionFills, s.UnlabelledVersionFills)
	b.WriteString("## 指纹生成\n\n训练只使用 positive/negative 指定快照。测试排除训练主机、相同响应与重复测试响应；生成结果重新从 YAML 加载、编译后测试。此处 passed 仅代表本批独立样本通过，仍输出候选规则供评审。\n\n| 计划 | 名称 | 独立测试 TP/FP/FN/TN | 版本 正确/错误/缺失 | 排除 | 结论 |\n|---|---|---|---|---:|---|\n")
	for _, g := range s.Generation {
		d := g.Detection
		v := g.Versions
		fmt.Fprintf(&b, "| %s | %s | %d/%d/%d/%d | %d/%d/%d | %d | %s |\n", g.Name, g.Product, d.TP, d.FP, d.FN, d.TN, v.Correct, v.Wrong, v.Missing, len(g.Excluded), g.Status)
		if g.Error != "" {
			fmt.Fprintf(&b, "\n%s: %s\n\n", g.Name, g.Error)
		}
	}
	b.WriteString("\n训练样本的自动版本推断另外记录在 generation.json 的 training_versions / training_cases；训练正确不等于独立验证通过。\n")
	b.WriteString("\n## 待核查\n\n")
	if len(s.Disagreements) == 0 {
		b.WriteString("已标注范围内没有分歧。\n")
	} else {
		for _, d := range s.Disagreements {
			fmt.Fprintf(&b, "- %s\n", d)
		}
	}
	fmt.Fprintf(&b, "\nProvider 调用 %d，完整输入精确缓存命中 %d，输入 token %d，耗时 %.1f 秒。费用未估算。\n\nbaseline.jsonl 保存输入；cleaned.jsonl 仅含成功完成的结果；rows.jsonl 保存拒绝、补回、补版本、名称建议及错误；generation.json 保存每个独立样本结果。\n", s.Requests, s.CacheHits, s.InputTokens, s.Seconds)
	return os.WriteFile(path, []byte(b.String()), 0600)
}
