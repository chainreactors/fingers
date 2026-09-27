package main

import (
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/judge"
	"github.com/chainreactors/fingers/judge/maintain"
	"github.com/chainreactors/utils/jev"
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
	got := versionOf(f)
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

// add is the same label comparison for scan, generation and library evaluation.
func (s *stageScore) add(label productLabel, frame *common.Framework) {
	s.Detection.add(label.Present, frame != nil)
	if label.Version != nil {
		s.Versions.add(frame, *label.Version)
	}
}

func (s stageScore) failed() bool {
	return s.Detection.FP > 0 || s.Detection.FN > 0 || s.Versions.Wrong > 0 || s.Versions.Missing > 0 || s.Versions.Unsupported > 0
}

type replaySummary struct {
	Schema                   int                   `json:"schema"`
	Model                    string                `json:"model"`
	BaselineSource           string                `json:"baseline_source"`
	Samples                  int                   `json:"samples"`
	UniqueHosts              int                   `json:"unique_hosts"`
	UniqueResponses          int                   `json:"unique_responses"`
	Errors                   int                   `json:"errors"`
	LabelledPairs            int                   `json:"labelled_pairs"`
	Baseline                 stageScore            `json:"baseline"`
	Accepted                 stageScore            `json:"accepted"`
	FalseHitsRemoved         int                   `json:"false_hits_removed"`
	TrueHitsRemoved          int                   `json:"true_hits_removed"`
	NaturalMissesRecovered   int                   `json:"natural_misses_recovered"`
	MissedProductsDiscovered int                   `json:"missed_products_discovered"`
	VersionFills             int                   `json:"version_fills"`
	CorrectVersionFills      int                   `json:"correct_version_fills"`
	IncorrectVersionFills    int                   `json:"incorrect_version_fills"`
	UnlabelledVersionFills   int                   `json:"unlabelled_version_fills"`
	Generation               []generationResult    `json:"generation"`
	Disagreements            []string              `json:"disagreements"`
	Options                  map[string]int        `json:"options"`
	Outcomes                 map[jev.Outcome]int   `json:"presence_outcomes"`
	JunkRules                []*maintain.RuleStats `json:"junk_rules"`
	Clusters                 []*maintain.Cluster   `json:"clusters"`
	Claims                   int                   `json:"claims"`
	Requests                 int                   `json:"provider_requests"`
	CacheHits                int                   `json:"exact_cache_hits"`
	InputTokens              int64                 `json:"input_tokens"`
	Seconds                  float64               `json:"seconds"`
}

func summarizeReplay(m *replayManifest, rows []record, gen []generationResult, clusters []*maintain.Cluster) replaySummary {
	out := replaySummary{Schema: 3, Clusters: clusters, Samples: len(m.Samples), Generation: gen, Options: map[string]int{}, Outcomes: map[jev.Outcome]int{}}
	missing := missingCandidates(clusters)
	hosts, hashes := map[string]bool{}, map[string]bool{}
	byID := map[string]record{}
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
		accepted := r.Judged.Accepted()
		for _, f := range r.Judged {
			if f != nil && f.Judge != nil && !f.Judge.Duplicate && f.Judge.Outcome != "" {
				out.Options[f.Judge.Option]++
				out.Outcomes[jev.Outcome(f.Judge.Outcome)]++
			}
		}
		for _, stage := range []struct {
			score  *stageScore
			frames common.Frameworks
		}{{&out.Baseline, r.Baseline}, {&out.Accepted, accepted}} {
			for _, l := range s.Labels {
				f := findLabel(stage.frames, l)
				stage.score.add(l, f)
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
			before, after := findLabel(r.Baseline, l), findLabel(accepted, l)
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
			if l.Present && after == nil && containsProductName(missing[r.ID], l) {
				out.MissedProductsDiscovered++
			}
			// Count a labelled product once, considering all baseline aliases.
			// Raw per-name changes remain in rows.jsonl for audit.
			if after != nil && versionOf(after) != "" && (before == nil || versionOf(before) == "") {
				out.VersionFills++
				switch {
				case !l.Present:
					out.IncorrectVersionFills++
				case l.Version == nil:
					out.UnlabelledVersionFills++
				case versionOf(after) == *l.Version:
					out.CorrectVersionFills++
				default:
					out.IncorrectVersionFills++
				}
			}
			if (after != nil) != l.Present {
				out.Disagreements = append(out.Disagreements, fmt.Sprintf("%s %s: presence want=%t got=%t", s.ID, l.Product, l.Present, after != nil))
			}
			if l.Version != nil && after != nil && versionOf(after) != *l.Version {
				out.Disagreements = append(out.Disagreements, fmt.Sprintf("%s %s: version want=%q got=%q", s.ID, l.Product, *l.Version, versionOf(after)))
			}
		}
		unlabelled := map[string]bool{}
		for _, f := range accepted {
			if f.Attributes == nil || f.Version == "" {
				continue
			}
			name := f.Name
			before := findLabel(r.Baseline, productLabel{Product: name})
			if before != nil && before.Attributes != nil && versionOf(before) != "" {
				continue
			}
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
func writeReplayReport(path string, s replaySummary, m *replayManifest) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# 真实响应回放评估\n\n模型：%s；基线：%s。\n\n%d 份快照，%d 个主机组，%d 种去除易变响应头后的响应，%d 个已标注产品判断，失败 %d 份。\n\n", s.Model, s.BaselineSource, s.Samples, s.UniqueHosts, s.UniqueResponses, s.LabelledPairs, s.Errors)
	b.WriteString("统计范围是保存的响应所支持的产品与版本。页面自报版本不是服务器安装审计；正负标注不代表完整技术栈。未标注的输出不计为误报，也不计为已证明正确。页面级结果含同主机响应，不能视作独立随机样本。\n\n")
	b.WriteString("| 阶段 | TP | FP | FN | TN | 未标注输出 |\n|---|---:|---:|---:|---:|---:|\n")
	for _, r := range []struct {
		name string
		s    stageScore
	}{{"原结果", s.Baseline}, {"Accepted", s.Accepted}} {
		d := r.s.Detection
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d |\n", r.name, d.TP, d.FP, d.FN, d.TN, r.s.UnlabelledPredictions)
	}
	fmt.Fprintf(&b, "\n有标注的误报移除 %d；真实命中误删 %d；自然漏报补回 %d。模型拒绝或新增的未标注项保留在 rows.jsonl 中供复核。\n\n", s.FalseHitsRemoved, s.TrueHitsRemoved, s.NaturalMissesRecovered)
	fmt.Fprintf(&b, "仍漏报的产品中，%d 项所在页面簇的 Coverage 判定为 missing，且产品名在代码给出的候选名中；不计作已识别，也不计作漏报补回。\n\n", s.MissedProductsDiscovered)
	b.WriteString("| 判定 | 产品数 |\n|---|---:|\n")
	for _, v := range []string{judge.OptionDeclared, judge.OptionAbsent, judge.OptionRunning, judge.OptionMentioned, judge.OptionUnrelated, jev.OptionInsufficient} {
		fmt.Fprintf(&b, "| %s | %d |\n", v, s.Options[v])
	}
	coverage := map[jev.Outcome]int{}
	for _, c := range s.Clusters {
		coverage[c.Outcome]++
	}
	b.WriteString("\n| Claim | holds | refuted | insufficient |\n|---|---:|---:|---:|\n")
	for _, row := range []struct {
		name string
		n    map[jev.Outcome]int
	}{{"Presence（误报，按产品）", s.Outcomes}, {"Coverage（漏报，按页面簇）", coverage}} {
		fmt.Fprintf(&b, "| %s | %d | %d | %d |\n", row.name, row.n[jev.Holds], row.n[jev.Refuted], row.n[jev.Insufficient])
	}
	fmt.Fprintf(&b, "\n共 %d 题（含缓存命中），平均每页 %.1f 题。\n\n", s.Claims, float64(s.Claims)/math.Max(float64(s.Samples), 1))
	b.WriteString("| 版本阶段 | 正确 | 错误 | 缺版本 | 正确留空 | 无依据填值 | 产品未识别 |\n|---|---:|---:|---:|---:|---:|---:|\n")
	for _, r := range []struct {
		name string
		s    versionScore
	}{{"原结果", s.Baseline.Versions}, {"Accepted", s.Accepted.Versions}} {
		v := r.s
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d | %d |\n", r.name, v.Correct, v.Wrong, v.Missing, v.CorrectAbstentions, v.Unsupported, v.ProductMissing)
	}
	fmt.Fprintf(&b, "\n按产品合并别名后的新增版本 %d：标注确认正确 %d、错误 %d、未标注 %d。已有非空版本保留，错误由报告揭示；逐名称变化见 rows.jsonl。\n\n", s.VersionFills, s.CorrectVersionFills, s.IncorrectVersionFills, s.UnlabelledVersionFills)
	b.WriteString("## 指纹生成\n\n训练只使用 positive/negative 指定快照。测试排除训练主机、相同响应与重复测试响应；生成结果重新从 YAML 加载、编译后测试。此处 passed 仅代表本批独立样本通过，仍输出候选规则供评审。\n\n| 计划 | 名称 | 训练 TP/FP/FN/TN | 训练版本 正确/错误/缺失 | 独立测试 TP/FP/FN/TN | 测试版本 正确/错误/缺失 | 排除 | 结论 |\n|---|---|---|---|---|---|---:|---|\n")
	plans := map[string]generationPlan{}
	for _, p := range m.Generation {
		plans[p.Name] = p
	}
	for _, g := range s.Generation {
		p := plans[g.Name]
		training, holdout, status := g.assess(m, p)
		d, v := holdout.Detection, holdout.Versions
		td, tv := training.Detection, training.Versions
		fmt.Fprintf(&b, "| %s | %s | %d/%d/%d/%d | %d/%d/%d | %d/%d/%d/%d | %d/%d/%d | %d | %s |\n", g.Name, p.Product, td.TP, td.FP, td.FN, td.TN, tv.Correct, tv.Wrong, tv.Missing, d.TP, d.FP, d.FN, d.TN, v.Correct, v.Wrong, v.Missing, len(g.Excluded), status)
	}
	for _, g := range s.Generation {
		if g.Error != "" {
			fmt.Fprintf(&b, "\n%s: %s\n\n", g.Name, g.Error)
		}
	}
	b.WriteString("\n## 垃圾规则候选\n\n至少 3 次判定命中、被否决不少于 50% 的规则。\n\n| 引擎 | 指纹 | 规则 / matcher | 命中 | 被否决 |\n|---|---|---|---:|---:|\n")
	for _, r := range s.JunkRules {
		matcher := ""
		if r.Matcher != "" {
			matcher = fmt.Sprintf("#%d `%s`", r.Rule, strings.ReplaceAll(r.Matcher, "|", "\\|"))
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %.0f%% |\n", r.Engine, r.Name, matcher, r.Hits(), 100*r.RefutedFraction())
	}
	b.WriteString("\n## 漏报（Coverage）\n\n至少 2 个独立主机的页面簇；Claim：规则已报告的产品解释了这个页面。候选名由代码从页面中抽取，供人命名，不作为选项。\n\n| 主机数 | 判定 | 已报告 | 候选名（前 3） | 样例 |\n|---:|---|---|---|---|\n")
	for _, c := range s.Clusters {
		ids := c.Samples
		if len(ids) > 3 {
			ids = ids[:3]
		}
		cands := c.Candidates
		if len(cands) > 3 {
			cands = cands[:3]
		}
		fmt.Fprintf(&b, "| %d | %s | %s | %s | %s |\n", c.Hosts, c.Coverage.Option, strings.Join(c.Reported, ", "), strings.ReplaceAll(strings.Join(cands, ", "), "|", "\\|"), strings.Join(ids, ", "))
	}
	b.WriteString("\ngeneration.json 的 training / holdout 保存逐样本原生 Framework 或 null，真值来自 manifest.json；训练正确不等于独立验证通过。\n")
	b.WriteString("\n## 待核查\n\n")
	if len(s.Disagreements) == 0 {
		b.WriteString("已标注范围内没有分歧。\n")
	} else {
		for _, d := range s.Disagreements {
			fmt.Fprintf(&b, "- %s\n", d)
		}
	}
	fmt.Fprintf(&b, "\nProvider 调用 %d，完整输入精确缓存命中 %d，输入 token %d，耗时 %.1f 秒。费用未估算。\n\nbaseline.jsonl 保存输入；cleaned.jsonl 仅含成功完成的结果；rows.jsonl 保存基线、全部判定注解和错误，discovery.json 按样本 ID 保存漏报簇；generation.json 保存每个独立样本结果。\n", s.Requests, s.CacheHits, s.InputTokens, s.Seconds)
	return os.WriteFile(path, []byte(b.String()), 0600)
}
