# 经真实响应验证的 Jev 增量指纹

本目录保存通过 `judgeeval -maintain` 生成、导出、重新编译、独立样本测试及原生加载检查的原生 YAML。每个文件附带数据来源、目录审计和验证范围；默认引擎的内置压缩资源仍按原有资源流程维护。

## 加载

```go
engine, err := fingers.NewEngine(fingers.FingersEngine)
if err != nil {
    return err
}
if err := engine.Fingers().LoadFromYAML("fingerprints/jev-maintained-20260926.yaml"); err != nil {
    return err
}
if err := engine.Compile(); err != nil {
    return err
}
hits, err := engine.DetectContent(rawHTTPResponse)
```

生成规则维持原生 `Finger` / `Frameworks` 语义。SearXNG 和 Wakapi 包含版本提取；IT Tools 在当前真实样本没有明确版本证据时只识别产品。

扩展测试报告见 [Jev 指纹库维护验证](../docs/jev-maintenance-validation-20260926.md)，运行数据和完整响应保存在本地 `.judge-data/expansion-20260926/`。这些指纹的结论仅适用于报告中列出的版本、样本和标注范围。
