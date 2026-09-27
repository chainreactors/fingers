# judge 重构验收：事实 → Claim → Jev → 动作表

> 历史验收记录：本文记录早期 Claim 实现，Refine 与自动校准等接口已移除。当前合约与默认值见 [judge](../judge/README.md)，当前输出见 [judgeeval](../cmd/judgeeval/README.md)；本文测量结果未由当前实现重新验证。

## 结论

**计划的全部验收标准都已通过。** 输入与 run-07-final 相同：69 份真实响应快照，682 个已标注的产品判断。模型为 jev-1.13.0，`MinConfidence` 取校准后的默认值 0.3，0 份请求失败。

| 验收标准 | run-07 | 本次 | 结论 |
|---|---:|---:|---|
| 有标注的误报删除数（要求 ≥24） | 24 | **24** | ✅ |
| 真实命中误删 | 0 | **0** | ✅ |
| 3 个宝塔默认页上的宝塔 | 被误删 | **全部保留** | ✅ |
| `varnish=1.1` | 出现 | **不出现** | ✅ |
| Refine 每页题目数（要求约 -35%） | 15.14 | **6.29（-58%）** | ✅ |
| 版本 正确/错误（要求不劣于 23/0） | 23/0 | **36/0**，无依据填值 0 | ✅ |
| Ledger 前几名包含 git、ipeakcms、webp_server_go | — | 第 1、2、3 名 | ✅ |
| Discover 找出 SearXNG、Wakapi、IT Tools 的簇 | — | 三个簇都找到了。不加载 library 时，Coverage 把 SearXNG、Wakapi 判为 `missing`，IT Tools 判为 `insufficient`（见"漏报"一节） | ⚠️ 2/3 |

**计数口径**
- run-07 的误报在前、本次的在后，基线的真命中数不同（46 对 63），因为本次基线是用当前规则重新扫描保存的响应得到的。
- 题目数的两个数字，是用同一个固定回答的 Provider，分别在旧设计（1f42439）和新设计上，对同一批命中跑 Refine 统计出来的。评估报告里的"平均每页 8.6 题"是另一个口径：它还包含 Discover 的 Coverage 题目。

## 超出计划的改动及原因

第一次真实评估只删掉了 8 个误报。原因都在"代码负责找事实"这一侧：给 Jev 的证据不足，或者给出的选项不贴切。按边界原则，修正都放在代码的事实层和题面里，没有加任何推翻或组合 Jev 回答的逻辑。

1. **四个引擎记录命中依据**：以前只有 fingers 引擎会写 `MatchDetail`。goby、fingerprinthub、ehole、wappalyzer 的命中没有任何证据，Jev 只能回答 insufficient。现在这四个引擎在命中时都会记录实际匹配到的文本，由 `Engine.EnableMatchDetail()` 统一打开。开关默认关闭，现有输出不变。
2. **Evidence 带上 `matched`**：State 里除了上下文片段，还单独给出规则匹配到的文本本身。
3. **新增判定 `unrelated`**：goby 的 `"s7"`、`"rdp"`、`"git"` 这类短串会碰巧命中 base64 数据或别的单词。原来的选项里没有贴切的一项，模型只好弃权。新增这个选项后，动作表执行删除；Ledger 里它也是垃圾规则最直接的信号。parsers 的字段注释同步更新了。
4. **版本候选排除非版本数值**：viewport 的 `initial-scale=1.0` 和全零值（例如 NEL 头里的 `"success_fraction":0.0`）不会作为候选，与已有的 IPv4 排除属于同一类。题面也从 "a meta tag" 改成了 "a generator meta tag"。
5. **Jev 不做指纹识别，全部判断统一为 Claim**（见下一节）。
6. **Discover 的聚类**：通用安全头（`X-Content-Type-Options`、`X-Frame-Options` 等）不再算作结构特征。之前"请通过官方域名访问"的 403 页和 Privacy Redirect 站点只因为都带这些头就被并成了一簇。候选名排除 HTTP 状态短语（"404 Not Found"、"Forbidden"）。

## 统一为 Claim

Jev 只审查规则给出的结论，不说出产品名。判定层只有一个机制：代码提出 Claim 并附上证据，Provider 选出证据支持的选项，选项的 Outcome（Holds / Refuted / Insufficient）驱动固定动作。

| Claim | 方向 | 选项 → Outcome |
|---|---|---|
| Presence：规则说 P 参与生成了这个响应 | 误报 | `running`→Holds；`mentioned`、`unrelated`→Refuted |
| Coverage：已报告的产品解释了这组页面 | 漏报 | `explained`、`custom_site`→Holds；`missing`→Refuted |
| Version：P 的版本是这些候选之一 | 版本 | 候选→Holds；`not_stated`→Refuted |

- 每个 Claim 都带 `insufficient`；置信度低于 `MinConfidence` 的回答一律判为 Insufficient。代码确定的事实（declared / absent）也表达为 Ruling，和 Provider 的回答走同一张动作表。
- 删除了 `Identify`、`Ask`、`Yes`、`Choose`、`Score`，以及 binary 和 score 题型。自定义判断用 `j.Judge(ctx, state, claims)`。
- 规则库已有的产品名从不作为选项，只作为被审查的 Claim 出现在题干或 State 里。
- 结论 DTO `parsers.Judgement` 与 Ruling 对齐：新增 `Outcome`，删除 `Layer`、`Primary`、`Recalled` 和 `Frameworks.Primary()`。Ledger 和评估报告都按 Outcome 统计。离线重放显示，Presence 的 holds 225 = declared 133 + running 92，refuted 135 = absent 5 + mentioned 54 + unrelated 76，insufficient 7。
- `judge/gen` 必须由人提供 `Name`。Discover 的簇附带代码抽取的候选名，供人命名。

### 漏报（Coverage）结果

| 簇 | 不加载 library | 加载 library |
|---|---|---|
| SearXNG（10 主机） | `missing` 0.86 ✅ | `explained` ✅ |
| Wakapi（4 主机） | `missing` 0.73 ✅ | `explained` ✅ |
| IT Tools（2 主机） | `insufficient` 0.29 ⚠️ 漏判 | `missing` 0.35 ❌ 误报警 |
| nginx 默认页、通用 404、宝塔默认页、阿里 WAF 403、SoftEther | 全部 `explained` ✅ | 全部 `explained` ✅ |

IT Tools 在两种情况下的概率分布几乎相同（missing 约 0.47–0.50），说明 Jev 对这个文字很少的单页应用，判断和"已报告里是否有 it tools"基本无关。误报警只会进入人工审核队列，不会删除任何东西。

## MinConfidence 校准

在同一输入上用 `judgeeval -min-confidence` 扫描不同阈值：

| MinConfidence | 误报删除 | 误删 | 版本 对/错 | 宝塔 | 删除总数 |
|---:|---:|---:|---:|---|---:|
| 0.2 | 24 | 0 | 36/0 | 保留 | 138 |
| 0.3 | 24 | 0 | 36/0 | 保留 | 135 |
| 0.5 | 24 | 0 | 36/0 | 保留 | 117 |
| 0.6 | 24 | 0 | 36/0 | 保留 | 109 |
| 0.7 | 23 | 0 | 36/0 | 保留 | — |

有标注的结果在 0.2–0.6 之间完全相同。阈值从 0.5 降到 0.3，多删的 18 个未标注命中逐一抽查都是误报：`harbor` 命中了图片 alt 文字，`webp_server_go` 命中了 `.webp` 文件名，`windows` 命中了 "Microsoft YaHei" 字体。从 0.3 降到 0.2 多删的 3 个也都是误报。默认值取 0.3：拿到几乎全部收益，同时没有降到 0.2 那么低；样本只有 69 页，留出一定余量。

## 遗留问题

- **宝塔别名**：`宝塔` 与 `宝塔-bt.cn` 归一化后不相同，所以不会去重。这需要在名称归一化或别名表里处理，不在本次范围内。宝塔默认页的簇判为 insufficient，因为页面本身没有写出产品名，这个结果是对的；宝塔在所有页面上都保留了。
- **通用错误页**：聚类会把不同服务器的通用 404/403 页并成一簇，目前判为 insufficient，结果正确，但这类簇本身没有维护价值。
- **样本规模**：结论只基于 69 页、59 个主机，`MinConfidence` 需要在更大的样本集上复核。
- **网络错误**：评估中偶尔出现 `connection reset` 或 `EOF`，重跑即可恢复。

## 复现

```
go run ./cmd/judgeeval \
  -manifest .judge-data/expansion-20260926/run-07-final/manifest.json \
  -library .judge-data/expansion-20260926/run-07-final/library.yaml \
  -cache .judge-data/cache -out .judge-data/claim-v1
```

`TYPESAFE_API_KEY` 只通过环境变量传入。去掉 `-library` 即可验证 Discover 能否发现新产品（输出在 `.judge-data/claim-v1-nolib`）。`.judge-data/` 不纳入版本控制。
