# Jev 真实响应验证：2026-09-25

## 结论

已经用新采集的真实 HTTP 响应跑通保存结果清洗、逐产品版本补全、名称建议、候选指纹生成、原生 YAML 导出加载和离线回放。发现的问题已修复并重新评估。

在本批已标注范围内，清洗移除 24 个误报，没有误删真实命中；新增 20 个正确版本。自然漏报仍有 3 个，没有被自动补回。6 项指纹生成实验中，3 项通过独立样本测试，另外 3 项独立正例不足。不能据此宣称全部功能已经验证充分，或推断全网误报率为零。

主报告：[run-03/report.md](../.judge-data/run-03/report.md)；机器指标：[run-03/metrics.json](../.judge-data/run-03/metrics.json)；离线复现：[run-04/report.md](../.judge-data/run-04/report.md)。原始响应和模型缓存均留在本机 Git 忽略目录 `.judge-data/`。

## 数据与标注

- 2026-09-25 22:18:17–22:18:19（北京时间）重新采集；来源为用户指定 `47.239.11.0/24` 内的 HTTP/HTTPS 页面及 3 份 `/robots.txt` 响应。
- 共 35 份响应、30 个主机组、31 种去除易变响应头后的响应；本批明确 URL 列表采集失败 0 项。这是选定的响应集合，不是完整网段可用性普查或全网随机代表样本。
- 138 个产品正负标注，其中 49 个包含版本标注。版本缺省表示未标注，空字符串表示该响应没有可归属的版本证据，非空字符串表示期望的完整版本。
- 标注依据为原始响应头、generator meta、资源路径、页面产品归属及保存的原文片段。加载时检查 SHA256、HTTP 完整性和证据片段是否存在；证据是否足以支持结论仍需要复核。
- 标注不来自 Jev 的答案，不输入清洗或版本判定。真值定义为“响应证据支持的产品和版本”，不是服务器安装审计；IP 抓取也不能覆盖域名虚拟主机的所有内容。
- 页面自报版本、产品头和资产版本都可能与实际安装状态不同。同一主机多份响应不视作独立统计样本；未标注输出不能算作已证明正确或误报。

首次标注复核后修正了两项：New API 的 `X-New-Api-Version: v1.0.0-rc.35`，以及 ThinkPHP 产品归属下的 `<span>V8.1.2</span>`。修订前后值和原文保存在 [label-review.json](../.judge-data/real-20260925/label-review.json)。最终各阶段统一按修订后的标签计分。

## 清洗、误报与漏报

计数单位是已标注的“响应 × 产品”。产品名称按规范化名称及显式别名匹配，不使用子串判断。

| 阶段 | TP | FP | FN | TN | 未标注输出 |
|---|---:|---:|---:|---:|---:|
| 保存的原规则结果 | 46 | 24 | 3 | 65 | 74 |
| Refine | 46 | 0 | 3 | 89 | 28 |
| 再对各产品补版本 | 46 | 0 | 3 | 89 | 28 |

- 已标注误报移除 24，真实命中误删 0，自然漏报恢复 0；35 份响应全部完成，无失败行。
- 剩余漏报：Nutz（`c31d254bc1fd0230`）、aaPanel（`afac5614625bfc6f`）、New API（`05346dbcf28946f0`）。
- 名称建议覆盖 Nutz 和 New API 两项，但建议没有成为已接受的指纹命中，因此不计作漏报恢复。
- 清洗后仍有 28 个未标注输出，尚不能由本批标签判断其准确性。

本次 `-history` 使用的是本批新响应首次运行时保存的 `baseline.jsonl`。这证明“保存结果 → 重新判定 → 清洗结果”机制可用，不代表覆盖长期生产历史分布。

## 版本补全

| 阶段 | 正确 | 错误 | 缺版本 | 正确留空 | 无依据填值 | 产品未识别 |
|---|---:|---:|---:|---:|---:|---:|
| 原规则结果 | 3 | 0 | 20 | 23 | 0 | 3 |
| Refine | 9 | 0 | 14 | 23 | 0 | 3 |
| 各保留产品分别调用 Version | 23 | 0 | 0 | 23 | 0 | 3 |

`Refine` 只补主产品的版本；独立 `Version` 调用验证剩余保留产品的空版本。正确非空版本从 3 增至 23，净新增 20 项。另有 2 项新增版本未标注，不计入正确项。按产品合并别名，基线任一别名已有版本即不算新增；逐名称变化仍保存在 `rows.jsonl`。

已有非空版本保留。本批没有已标注的错误历史版本，因此“修正一个已有但错误的版本值”未在本批验证，也不是这里的补空值操作。漏报产品的版本记为“产品未识别”，不能冒充正确留空。

## 指纹生成与加载

真实正反例经 `NewGenerator → Positive/Negative → Generate` 生成原生指纹。自动命名计划使用 `SuggestNames`；版本从普通 `Positive` 自动推断，不向生成器传入评估标签。导出 YAML 后重新加载、编译，并通过原生 `PassiveMatch` 或录制探测响应的 `ActiveMatch` 测试。

训练和测试按主机组、实际 hostname、去除易变头的响应内容隔离；测试集还排除重复响应。以下计数均为未参加训练的独立响应，TP/FP/FN/TN 顺序固定。

| 计划 | 独立 TP/FP/FN/TN | 独立版本结果 | 结论 |
|---|---|---|---|
| nginx-auto | 13/0/0/5 | 4 个正确版本，9 个正确留空 | passed_holdout |
| caddy-auto | 2/0/0/18 | 2 个正确留空 | passed_holdout |
| apache-auto-version | 2/0/0/17 | 2 个正确留空 | passed_holdout |
| caddy-active | 0/0/0/0 | 无独立样本 | insufficient_holdout |
| new-api-candidate | 0/0/0/3 | 无独立正例版本 | insufficient_holdout |
| softether-candidate | 0/0/0/4 | 无独立正例版本 | insufficient_holdout |

训练版本单独统计：nginx 为 2 个正确版本，Apache 为 1 个，New API 为 1 个。New API 的候选规则已完整提取 `1.0.0-rc.35`，并采用版本头名称作为产品特征；这仅证明该训练响应上的生成机制，不能代替独立正例验证。Apache 的版本提取也只在本批训练响应得到验证。

Caddy 主动规则已在录制的训练探测响应上完成匹配；其剩余正例探测响应与训练内容重复，被剔除。SoftEther 的另一主机返回相同页面，也被剔除。New API 只有一个正例主机。候选文件保存在 [run-03/fingerprints](../.judge-data/run-03/fingerprints)，未直接写入发布指纹库。

## 真实证据推动的修复

1. **协议特征误保留**：HTTP Basic 等指纹原先被无条件信任。现在需要对应响应头证据；正文提及认证或错误命中不能绕过清洗。
2. **版本被截断**：统一版本 token，保留 OpenSSL `1.0.2q`、预发布 `1.0.0-rc.35`、`8.1SP2` 等后缀，支持脚本文件名的版本边界。
3. **版本候选被噪声挤掉**：先收集再按证据排序，避免前部大量数字挤掉后部 generator、响应头或资源版本。
4. **生成规则绑定单一版本**：`X-*-Version` 使用头名称识别产品，并独立提取版本；生成头规则时规范化产品名。
5. **评估夸大改进**：修正别名重复统计，区分名称建议与真正补回漏报，未识别产品不计为版本留空成功，错误行及未标注输出单列。

对应回归位于 [judge/real_evidence_test.go](../judge/real_evidence_test.go) 和 [cmd/judgeeval/replay_test.go](../cmd/judgeeval/replay_test.go)。最小证据回归包含受控构造，不加入真实样本数量或真实准确率统计。

## 回放与复现

每个运行目录保存原始响应副本、相对路径 manifest、SHA256、原始及清洗后 Frameworks、逐项结果、生成 YAML 和 Go 构建信息。响应快照可独立加载；严格离线的模型答案还需要保留指定的精确缓存目录。

| 运行 | 用途 | Provider 请求 | 精确缓存命中 | 输入 tokens |
|---|---|---:|---:|---:|
| run-01 | 首轮真实响应评估 | 180 | 41 | 313,477 |
| run-02 | 证据修复后评估 | 30 | 190 | 64,248 |
| run-03 | 最终计数及训练版本核验 | 0 | 220 | 0 |
| run-04 | 无凭据严格离线回放 run-03 快照 | 0 | 220 | 0 |

模型标识为 `jev/jev-1.13.0`。精确缓存键包含模型、endpoint、完整状态和问题，评估禁用近似页面缓存。离线缓存缺失直接报错，测试已确认不会回退调用 Provider。最终回放检查：除耗时外指标一致；manifest、baseline、cleaned、rows、generation 的 JSON 内容一致；6 个 YAML 文件逐字节一致。复现证明输入与已保存模型回答的确定性，不等于重新远程请求模型后的稳定性试验。

```powershell
go build -tags goregexp -o bin/judgeeval.exe ./cmd/judgeeval
# 使用新目录，已有结果拒绝覆盖。离线无需 TYPESAFE_API_KEY。
./bin/judgeeval.exe -offline -manifest .judge-data/run-03/manifest.json -history .judge-data/run-03/baseline.jsonl -cache .judge-data/cache -out .judge-data/run-reproduce -rps 8

go test -short -tags goregexp ./judge ./judge/jev ./cmd/judgeeval . ./cmd/engine -count=1 -timeout 3m
git diff --check
```

本次受影响包测试及 diff 检查通过。全仓库测试尚有此前存在的 benchmark go-re2 依赖和 nmap/fingerprinthub 旧接口问题，不在本次修复范围，不能声称全仓库测试通过。

后续验证缺口集中在：3 个自然漏报、错误非空历史版本、New API/SoftEther/Caddy 主动规则的独立正反例，以及跨网段、跨版本和跨时间的新批次。现有报告已明确区分“已执行”“本批通过”和“证据不足”。
