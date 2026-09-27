
## Introduce

多指纹库聚合识别引擎.  当前支持`fingers(主指纹库)` `wappalyzer`, `fingerprinthub`, `ehole`, `goby` 指纹

不用再挑选指纹识别的工具, AllInOne一站式实现

使用了fingers的工具: 

* ⭐ [spray](https://github.com/chainreactors/spray) **最佳实践**, 集合了目录爆破, 指纹识别, 信息收集等等功能的超强性能的http fuzz工具
* [gogo](https://github.com/chainreactors/gogo), 使用了fingers原生指纹库, 红队向的自动化扫描引擎
* [zombie](https://github.com/chainreactors/zombie), 在爆破前使用fingers进行指纹验证, 提高爆破效率

(任何使用了fingers的工具欢迎在issue中告诉我, 我会将你的工具添加到这里)

## Features

* 支持多指纹库聚合识别
  * ✅ fingers 原生指纹库
  * ✅ [wappalyzer](https://github.com/projectdiscovery/wappalyzergo)
  * ✅ [fingerprinthub](https://github.com/0x727/FingerprintHub)
  * ✅ [ehole](https://github.com/EdgeSecurityTeam/EHole)
  * ✅ goby
* 支持多指纹源favicon识别
* 超强性能, 单个站点识别 <100ms. 重写了各指纹库的引擎, 并极大优化了性能
* 聚合输出, 多指纹库的结果将会自动整合
* 支持CPE的URI, FSB, WFN格式输出

### morefingers

https://github.com/chainreactors/morefingers

fingers的拓展引擎, 有更全更大的指纹库.

从对闭源工具的逆向得到的指纹库, 为了避免可能存在的纠纷, 不提供开源版本. 

## QuickStart

`go get github.com/chainreactors/fingers@master`

支持 Go 1.17 及以上。规则正则默认使用标准库；在 Go 1.24 及以上可以换成更快的 RE2，只需额外引入一行：

```golang
import _ "github.com/chainreactors/fingers/re2" // go get github.com/chainreactors/fingers/re2
```

### Example

document: https://chainreactors.github.io/wiki/libs/fingers/

调用内置所有进行指纹引擎识别, 示例:

```golang
func TestEngine(t *testing.T) {
    engine, err := NewEngine()
    if err != nil {
       panic(err)
    }
    resp, err := http.Get("http://127.0.0.1:8080/")
    if err != nil {
       return
    }
    content := httputils.ReadRaw(resp)
    frames, err := engine.DetectContent(content)
    if err != nil {
        return
    }
    fmt.Println(frames.String())
}
```

调用SDK识别Favicon指纹, 示例:

```golang
func TestFavicon(t *testing.T) {
    engine, err := NewEngine()
    if err != nil {
        panic(err)
    }
    resp, err := http.Get("http://baidu.com/favicon.ico")
    if err != nil {
        return
    }
    content := httputils.ReadRaw(resp)
    body, _, _ := httputils.SplitHttpRaw(content)
    frame := engine.DetectFavicon(body)
    fmt.Println(frame.String())
}
```

更多用法请见: https://chainreactors.github.io/wiki/libs/fingers/sdk/

## 判定层 judge

规则引擎召回能力强，但会有误报、多个引擎的同名重复，也会漏掉规则库里没有的产品，版本号更是难以拿准。`judge` 包在规则结果之上加了一层审查：**它只审查规则给出的结论，不做指纹识别，模型从不说出产品名。** 它不是新的引擎，`WebMatch` 和 `DetectContent` 的行为保持不变。Claim 合约、缓存和 [TypeSafe Jev](https://docs.typesafe.ai/api.md) 客户端在 [`github.com/chainreactors/utils/jev`](https://github.com/chainreactors/utils/tree/master/jev)，fingers 只保留指纹相关的断言。

判定层只有一个机制，即 Claim：代码提出断言并附上证据，Provider 选出证据支持的选项，选项的 Outcome（holds / refuted / insufficient）驱动固定动作。去误报（Presence）、找漏报（Coverage）、确认版本（Version）都是 Claim；与指纹无关的自定义 Claim 直接用 `jev.Judge`。

```golang
engine.EnableMatchDetail()                        // 让 Claim 能引用规则命中的原文
c, _ := jev.NewClient("")                         // 读取 TYPESAFE_API_KEY
j := judge.New(jev.Cached(c, jev.DefaultCacheSize)) // 一个扫描任务共用一个 Judge

hits, _ := engine.DetectContent(raw)              // 同步，纯规则
all, err := j.Inspect(ctx, raw, hits)             // 一次完成 presence 与 version，保留全部注解
accepted := all.Accepted()                       // 上报视图：排除拒绝和重复条目
if err != nil {
    accepted = hits                               // 判定失败时退回纯规则结果；hits 从不被修改
}
for _, f := range accepted {
    if f.Judge != nil {                           // nil：未经判定（如超过每页 40 个产品的上限）
        fmt.Println(f.Name, f.Version, f.Judge.Option, f.Judge.Outcome)
    }
}
```

判定结论是 `Framework.Judge` 字段（选项、Outcome、置信度、证据、是否剔除、是否重复），随现有输出一起序列化；下游不 import judge 也能用 `frames.Accepted()` 读取。被剔除的条目和原因已经包含在 `all` 中，无须再次请求 Provider。漏报在离线维护中处理：`judge/maintain.Discover` 把多个主机上的同一页面聚成簇，逐簇提出 Coverage Claim，判为 missing 的簇连同候选名交给人命名，再用 `judge/gen` 生成规则。

**数据外发**：判定时会把响应的精简视图发给 Provider，包括响应头（去掉 Date、Set-Cookie 值等无关头）、Cookie 名、标题、generator/description、脚本和样式路径、内联脚本开头、HTML 注释、表单字段名，以及正文前 1500 字。扫描授权范围内的目标前，请确认允许把这些内容发送给第三方服务。

当前实现于 2026-09-27 在 69 份已标注的真实响应上复测（jev-1.13.0）：误报 24 → 0，真实命中误删 0，版本正确 36、错误 0；不加载新增规则时 Discover 找出全部 3 个漏报产品，加载后无误报警。见 [复测报告](docs/jev-claim-retest-20260927.md)。

指纹判定的完整能力见 [judge/README.md](judge/README.md)；用正反样本生成原生指纹见 `judge/gen`；设计讨论见 [#34](https://github.com/chainreactors/fingers/issues/34)。

## fingers 引擎

fingers指纹引擎是目前特性最丰富, 性能最强的指纹规则库.

*  支持多种方式规则配置
*  支持多种方式的版本号匹配
*  404/favicon/waf/cdn/供应链指纹识别
*  主动指纹识别
*  超强性能, 采用了缓存,正则预编译,默认端口,优先级等等算法提高引擎性能
*  重点指纹,指纹来源与tag标记


### 内置指纹库

指纹库位于: https://github.com/chainreactors/templates/tree/master/fingers

文档: https://chainreactors.github.io/wiki/libs/fingers/rule/

tcp指纹与http指纹为同一格式, 但通过不同的文件进行管理

### 完整的配置

fingers设计的核心思路是命中一个指纹仅需要一条规则, 因此配置的多条规则中, 只需要任意一条命中即标记为命中, 需要在编写指纹的时候注意找到最能匹配目标框架的那条规则.

一个完整的配置:

```yaml
- name: frame   # 指纹名字, 匹配到的时候输出的值
  default_port: # 指纹的默认端口, 加速匹配. tcp指纹如果匹配到第一个就会结束指纹匹配, http则会继续匹配, 所以默认端口对http没有特殊优化
    - '1111'
  protocol: http  # tcp/http, 默认为http
  rule:
   - version: v1.1.1 # 可不填, 默认为空, 表示无具体版本
     regexps: # 匹配的方式
        vuln: # 匹配到vuln的正则, 如果匹配到, 会输出framework为name的同时, 还会添加vuln为vuln的漏洞信息
          - version:(.*) # vuln只支持正则,  同时支持版本号匹配, 使用括号的正则分组. 只支持第一组
        regexp: # 匹配指纹正则
          - "finger.*test" 
       # 除了正则, 还支持其他类型的匹配, 包括以下方式
        header: # 仅http协议可用, 匹配header中包含的数据
          - string
        body: # 包含匹配, 非正则表达式
          - string
        md5: # 匹配body的md5hash
          - [md5]
        mmh3: # 匹配body的mmh3hash
          - [mmh3]
          
        # 只有上面规则中的至少一条命中才会执行version
        version: 
          - version:(.*)  # 某些情况下难以同时编写指纹的正则与关于版本的正则, 可以特地为version写一条正则

     favicon: # favicon的hash值, 仅http生效
        md5:
          - f7e3d97f404e71d302b3239eef48d5f2
        mmh3:
          - '516963061'
     level: 1      # 0代表不需要主动发包, 1代表需要额外主动发起请求. 如果当前level为0则不会发送数据, 但是依旧会进行被动的指纹匹配.
     send_data: "info\n" # 匹配指纹需要主动发送的数据
     vuln: frame_unauthorized # 如果regexps中的vuln命中, 则会输出漏洞名称. 某些漏洞也可以通过匹配关键字识别, 因此一些简单的poc使用指纹的方式实现, 复杂的poc请使用-e下的nuclei yaml配置

```

为了压缩体积, 没有特别指定的参数可以留空会使用默认值。

在两个配置文件中包含大量案例可供参考。

但实际上大部分字段都不需要配置, 仅作为特殊情况下的能力储备。

每个指纹都可以有多个rule, 每个rule中都有一个regexps, 每个regexps有多条不同种类的字符串/正则/hash


## TODO 

- [x] 指纹名重定向, 统一多指纹库的同一指纹不同名问题
- [x] 指纹黑名单, 用于过滤指纹库中的垃圾指纹
- [x] 更丰富的CPE相关特性支持
- [ ] 更优雅的与nuclei或其他漏洞库联动
- 支持更多引擎
  - [ ] [nuclei technologies](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/technologies) 实现
  - [ ] fingerprinthub v4
  - [ ] tidefinger
  - [ ] kscan
  - [ ] nmap

## Thanks

* [wappalyzer](https://github.com/projectdiscovery/wappalyzergo)
* [fingerprinthub](https://github.com/0x727/FingerprintHub)
* [ehole](https://github.com/EdgeSecurityTeam/EHole)
* goby @XiaoliChan @9bie
