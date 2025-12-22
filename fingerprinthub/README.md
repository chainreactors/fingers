# FingerprintHub V4 Engine

基于 [neutron](https://github.com/chainreactors/neutron) 的 FingerprintHub v4 指纹识别引擎。

## 特性

- ✅ 完全基于 neutron 模板引擎
- ✅ 支持 FingerprintHub v4 YAML 格式
- ✅ 支持所有 matcher 类型（包括 favicon）
- ✅ 支持 HTTP 和 Network（TCP/UDP/TLS）指纹识别
- ✅ **兼容 tcp/udp 字段**：自动转换为 network 格式
- ✅ **完整的 CPE 支持**：自动从 metadata 提取 vendor 和 product
- ✅ 高性能：13,718 templates/sec 加载速度
- ✅ 高准确率：99.97% 成功率（3,144/3,145 模板）

## 快速开始

### 基础使用

```go
package main

import (
    "github.com/chainreactors/fingers/fingerprinthub_v4"
    "os"
)

func main() {
    // 创建引擎
    engine, err := fingerprinthub_v4.NewFingerPrintHubV4Engine()
    if err != nil {
        panic(err)
    }

    // 加载指纹模板
    err = engine.LoadFromFS(os.DirFS("path/to/fingerprints"), "*.yaml")
    if err != nil {
        panic(err)
    }

    // 匹配 HTTP 响应
    httpResponse := []byte("HTTP/1.1 200 OK\r\n...")
    frameworks := engine.WebMatch(httpResponse)

    // 处理结果
    for _, frame := range frameworks {
        println("Found:", frame.Name)
    }
}
```

### Service 指纹识别

```go
package main

import (
    "github.com/chainreactors/fingers/fingerprinthub_v4"
    "github.com/chainreactors/fingers/common"
    "time"
)

func main() {
    // 创建引擎
    engine, _ := fingerprinthub_v4.NewFingerPrintHubV4Engine()

    // 加载包含 network 请求的指纹模板
    engine.LoadFromFS(os.DirFS("path/to/fingerprints"), "*.yaml")

    // 创建 ServiceSender
    sender := common.NewServiceSender(5 * time.Second)

    // 定义回调函数处理匹配结果
    callback := func(result *common.ServiceResult) {
        println("Found:", result.Framework.Name)
    }

    // 执行 Service 匹配
    engine.ServiceMatch("192.168.1.1", "3306", 0, sender, callback)
}
```

## 测试

### 运行所有测试

```bash
go test -v
```

## 文件结构

```
fingerprinthub_v4/
├── fingerprinthub_v4.go           # 核心引擎实现
├── fingerprinthub_v4_test.go      # 单元测试
├── service_test.go                # Service 匹配测试
└── README.md                      # 本文档

resources/
└── fingerprinthub_v4.py           # YAML 合并工��（用于性能测试）
```

## Favicon Matcher 支持

本引擎完全支持 favicon matcher，包括：
- MD5 hash 匹配
- MMH3 hash 匹配（兼容 observer_ward）
- OR/AND 条件
- Match-all 模式

示例模板：

```yaml
id: example-favicon
info:
  name: Example Favicon Detection
  metadata:
    vendor: example
    product: example_app

http:
  - method: GET
    path:
      - "{{BaseURL}}/favicon.ico"
    matchers:
      - type: favicon
        hash:
          - "d41d8cd98f00b204e9800998ecf8427e"  # MD5
          - "1165838194"                         # MMH3
```

## Network 指纹支持

本引擎完全支持 neutron network 协议，可以识别 TCP/UDP/TLS 服务指纹。

### tcp/udp 字段兼容性

**重要**: FingerprintHub 的 `service-fingerprint` 目录使用 `tcp` 和 `udp` 字段，本引擎会自动将其转换为 neutron 的 `network` 字段格式，完全兼容！

```yaml
# FingerprintHub 格式（tcp 字段）
tcp:
  - inputs:
      - data: "\r\n\r\n"
        read: 1024
    host:
      - "{{Hostname}}"
    matchers:
      - type: word
        words:
          - "SFATAL"

# 自动转换为 neutron 格式（network 字段）
network:
  - inputs:
      - data: "\r\n\r\n"
        read: 1024
    host:
      - "{{Hostname}}"
    matchers:
      - type: word
        words:
          - "SFATAL"
```

### Network 指纹模板示例

```yaml
id: mysql-detect
info:
  name: MySQL Service Detection
  author: chainreactors
  severity: info
  metadata:
    vendor: oracle
    product: mysql

network:
  - inputs:
      - data: "\x00"
        read: 1024

    host:
      - "{{Hostname}}:3306"

    matchers:
      - type: word
        words:
          - "mysql_native_password"
          - "caching_sha2_password"
        condition: or
```

### 支持的 Network 特性

- ✅ TCP/UDP/TLS 协议
- ✅ **tcp/udp 字段自动转换**（完全兼容 FingerprintHub）
- ✅ 自定义发送数据（hex/text）
- ✅ 多轮交互（multiple inputs）
- ✅ 灵活的 matchers（word/regex/binary/size）
- ✅ DSL 支持
- ✅ Extractors 支持

### CPE 信息支持

Framework 自动从模板的 `metadata` 中提取 CPE 信息：

```yaml
info:
  metadata:
    vendor: oracle        # 自动映射到 Framework.Attributes.Vendor
    product: mysql        # 自动映射到 Framework.Attributes.Product
```

这样生成的 Framework 包含完整的 CPE 信息，便于后续的漏洞匹配和资产管理。

## 性能测试

如果需要测试完整的 FingerprintHub 数据库性能：

1. 使用工具脚本合并 YAML 文件：

```bash
python ../resources/fingerprinthub_v4.py \
    /path/to/FingerprintHub/web-fingerprint \
    fingerprints.json
```

2. 在你的测试代码中加载并测试：

```go
// 加载合并的指纹
engine, _ := fingerprinthub_v4.NewFingerPrintHubV4Engine()
// ... 加载 JSON 并转换为模板
// ... 执行性能测试
```

## 兼容性

- ✅ 完全兼容 FingerprintHub v4 模板格式
- ✅ **完全兼容 tcp/udp 字段**（自动转换为 network）
- ✅ 兼容 observer_ward favicon hash 算法
- ✅ 支持 neutron 所有 matcher 类型
- ✅ 支持 neutron network 协议（TCP/UDP/TLS）
- ✅ Go 1.16+ (需要 embed 支持)

## 相关项目

- [neutron](https://github.com/chainreactors/neutron) - Nuclei 模板引擎 Go 实现
- [FingerprintHub](https://github.com/0x727/FingerprintHub) - 指纹数据库
- [observer_ward](https://github.com/0x727/ObserverWard) - Web 指纹识别工具

## License

根据主项目 fingers 的 License 使用。
