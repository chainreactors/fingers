# judgeeval：纯规则 vs 规则 + judge

在一批原始 HTTP 响应上，用和 SDK 调用方完全相同的路径（`engine.DetectContent` → `engine.Refine`）跑一遍，逐项对比纯规则结果和经过判定之后的结果。它也用来校准新的 Provider。

```bash
go build -buildvcs=false -tags goregexp -o judgeeval ./cmd/judgeeval

# 标注集（仓库自带 40 页合成样本，含真值）
TYPESAFE_API_KEY=... ./judgeeval -provider jev -samples testdata/samples -labels testdata/labels.json

# 任意真实页面目录（*.http，完整的原始响应）
TYPESAFE_API_KEY=... ./judgeeval -provider jev -samples cc/samples -cache judgecache -out judgereport -rps 15
```

- 答案缓存在 `-cache` 目录，重跑不花钱，中断后可以接着跑。这个目录用的是精确缓存，另外会模拟相似度缓存：按签名距离分档，统计每一档能复用多少答案、与真实答案的一致率，用来确定 `judge.SimilarDistance` 的取值。
- `report.md`：对比表，另附页面类型分布、各引擎的否决率、否决率最高的规则（需要修复），以及新指纹候选。
- `rows.jsonl`：每页一行，用于人工复核。
- 给了 `-labels` 时，额外按真值统计误报剔除、真实命中保留、页面类型、通用页面和版本号的正确率。
- 新 Provider：在 `main.go` 的 `newProvider` 里注册。

没有真值的数据集用两个代理指标：
- **仅正文出现的命中**：代码判断出的疑似误报；
- **版本号**：以页面上的 generator meta 作为参考答案。

真实网站的页面属于第三方内容，不要提交进仓库。
