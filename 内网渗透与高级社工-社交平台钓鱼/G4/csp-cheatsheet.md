# CSP 速查

## 一、CSP 到底有什么用

CSP（Content Security Policy）是**由浏览器强制执行、作用于"单个文档"的声明式安全策略**。它随 HTTP 响应头下发，规定这个页面：

1. **能向哪些源发起请求**（脚本、样式、图片、字体、fetch/WebSocket、iframe…）
2. **能执行哪些代码**（内联 `<script>`、`onclick=`、`eval`、内联 `style`）
3. **能否被嵌进 iframe**、表单能提交到哪、`<base>` 能被设成什么

核心用途：**缓解 XSS 与恶意资源注入**——即使注入成功了，脚本也跑不起来、数据也发不出去。

三条必须记住的边界：

- CSP 是**纵深防御**，不替代输出编码、参数化查询、服务端校验。
- CSP **管不住已被信任的脚本**：`script-src 'self'` 下同源脚本（如 JSONP 回调）拥有该源的全部权限。
- CSP 是**浏览器端执行约束**，服务端漏洞、CSRF、Cookie 的 SameSite、跨源读取授权（CORS）都不归它管。

---

## 二、唯二的两种下发方式

### 1. HTTP 响应头（首选）

```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-<随机值>'
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report
```

- `Content-Security-Policy` = 强制执行
- `Content-Security-Policy-Report-Only` = **只上报不拦截**，上线前探路用
- 可下发**多个**同名头，策略**取交集**（最严格者生效），只会更严不会更松

### 2. `<meta>` 标签（次选，功能受限）

```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'">
```

- 只有 `http-equiv="Content-Security-Policy"` 这一种形式，**没有 Report-Only 版本**
- **`frame-ancestors`、`report-uri`、`report-to`、`sandbox` 在 meta 中无效**，只能走响应头
- 必须出现在 `<head>` 中且先于任何被约束的资源；解析顺序靠后则前面的资源已加载

---

## 三、指令对查表

——指令管的是"哪一类资源或行为"

### 3.1 取源类（fetch directives）——用"源"作为匹配单位

| 指令                 | 管什么                                                               | 兜底链（未写时向上取）                                |
| ------------------ | ----------------------------------------------------------------- | ------------------------------------------ |
| `default-src`      | **所有取源指令的兜底**                                                     | —                                          |
| `script-src`       | JS 脚本来源                                                           | `default-src`                              |
| `script-src-elem`  | 仅 `<script>` 元素 / 外部脚本                                            | `script-src` → `default-src`               |
| `script-src-attr`  | 仅事件属性（`onclick=` 等）与 `javascript:` URL                            | `script-src` → `default-src`               |
| `style-src`        | 样式表与内联样式                                                          | `default-src`                              |
| `style-src-elem`   | 仅 `<style>` 与 `<link rel=stylesheet>`                             | `style-src` → `default-src`                |
| `style-src-attr`   | 仅 `style="..."` 属性                                                | `style-src` → `default-src`                |
| `img-src`          | 图片、favicon                                                        | `default-src`                              |
| `font-src`         | 字体（`@font-face`）                                                  | `default-src`                              |
| `connect-src`      | fetch / XHR / WebSocket / EventSource / `sendBeacon` / `<a ping>` | `default-src`                              |
| `media-src`        | `<audio>` / `<video>` / `<track>`                                 | `default-src`                              |
| `object-src`       | `<object>` / `<embed>` / `<applet>`                               | `default-src`                              |
| `frame-src`        | **本页嵌别人**（iframe 加载源）                                             | `child-src` → `default-src`                |
| `child-src`        | 旧版 iframe/worker 兜底                                               | `default-src`                              |
| `worker-src`       | Worker / SharedWorker / ServiceWorker                             | `child-src` → `script-src` → `default-src` |
| `manifest-src`     | Web App Manifest                                                  | `default-src`                              |
| ~~`prefetch-src`~~ | 预取（已从规范移除，勿依赖）                                                    | —                                          |

> `connect-src` 天然包含 `'self'` 之外的 WebSocket；若用 `wss://` 必须显式列出（`https:` 不覆盖 `wss:`）。

### 3.2 导航 / 框架类——**不**回退到 `default-src`，必须单独写

| 指令                 | 管什么                                   | 备注                           |
| ------------------ | ------------------------------------- | ---------------------------- |
| `frame-ancestors`  | **谁能把我嵌进 iframe**（方向与 `frame-src` 相反） | 防点击劫持，现代替代 `X-Frame-Options` |
| `form-action`      | 表单能提交到哪些目标                            | 防表单外发数据；不覆盖 fetch            |
| `base-uri`         | `<base href>` 能设成什么                   | 防相对 URL 劫持；常配 `'none'`       |
| `sandbox`          | 给整个页面套 iframe sandbox 式能力削减           | meta 中无效                     |
| ~~`navigate-to`~~  | 顶层导航目标（未实装，已移除）                       | —                            |
| ~~`plugin-types`~~ | 插件 MIME 限制（CSP2 废弃）                   | —                            |

### 3.3 执行 / DOM 类——不涉及网络请求

| 指令                                   | 管什么                                               | 备注                                      |
| ------------------------------------ | ------------------------------------------------- | --------------------------------------- |
| `script-src` 的 `'unsafe-inline'`     | 放行内联脚本与事件属性                                       | 与 nonce/hash 同时存在时**被忽略**               |
| `script-src` 的 `'unsafe-eval'`       | 放行 `eval()` / `new Function()` / 字符串 `setTimeout` | 常被模板库和旧构建产物需要                           |
| `require-trusted-types-for 'script'` | 在 DOM API 层拒绝 `innerHTML = 字符串`                   | 需配 `trusted-types`；清洗器要返回 `TrustedHTML` |
| `trusted-types`                      | 允许创建 Trusted Type 的策略名白名单                         | 可加 `'allow-duplicates'`、`'none'`        |
| `style-src` 的 `'unsafe-inline'`      | 放行 `style="..."` 与 `<style>`                      | KaTeX / highlight.js 内联样式的常见痛点          |

### 3.4 传输 / 混合内容 / 上报类

| 指令                          | 管什么                         | 备注                           |
| --------------------------- | --------------------------- | ---------------------------- |
| `upgrade-insecure-requests` | http 子资源自动升级为 https         | 顶层导航不升级                      |
| `block-all-mixed-content`   | 阻止混合内容                      | 已被上一条取代，旧项目才见                |
| `report-uri`                | 违规报告上报地址（`csp-report` JSON） | 已废弃但仍广泛支持；meta 中无效           |
| `report-to`                 | 走 Reporting API 的现代上报       | 需配合 `Report-To` 响应头；meta 中无效 |
| ~~`require-sri-for`~~       | 强制 SRI（未广泛实装）               | —                            |

> 上报端点本身要防刷：攻击者可伪造海量报告打爆它。生产环境配合限流与采样。

---

## 四、来源表达式速查

——源跟在指令后面，管的是"这个指令管的资源或行为允许什么（白名单）"

| 表达式                                     | 含义                         | 安全性                       |
| --------------------------------------- | -------------------------- | ------------------------- |
| `'self'`                                | 同源（同 scheme + host + port） | 高（但 blob/data 匹配各浏览器有差异）  |
| `'none'`                                | 什么都不允许                     | 最高                        |
| `https://api.example.com`               | 精确源                        | 高                         |
| `*.example.com`                         | 该域任意子域                     | 中                         |
| `https:`                                | **任意** HTTPS 源             | 极低，白名单形同虚设                |
| `'unsafe-inline'`                       | 允许内联脚本/样式/事件属性             | **等于放弃脚本防护**              |
| `'unsafe-eval'`                         | 允许 `eval` 类动态执行            | 低                         |
| `'nonce-<base64>'`                      | 只放行带该 nonce 的内联脚本          | 高（须每响应随机、不可复用）            |
| `'sha256-<hash>'` / `sha384` / `sha512` | 只放行内容哈希匹配的内联脚本             | 高（内容一改就得改头）               |
| `'strict-dynamic'`                      | 信任链传递：受信脚本动态插入的脚本也受信       | 高（需配 nonce/hash；会忽略域名白名单） |
| `'report-sample'`                       | 报告中附带违规代码片段                | —                         |
| `'inline-speculation-rules'`            | 允许内联 speculation rules 脚本  | 较新                        |

**CSP 里没有 `'same-site'` 这类关键字**。匹配粒度是**源**和 host 通配；"站（eTLD+1）"属于 Cookie/SameSite 的概念。

我来补充：

**域/源**：必须端口、协议、域名（完全）三个都一样，才是同域；而仅仅是路径，可以不同。比如js的fetch请求等，采用的是同源策略（SOP）。

**站**：只要主域名和协议一致，就是同站，比如都是example.com主域名。  
——同域就类似自己与自己对话，同站就类似我们是一个集体的。

---

## 五、收到一份策略时的对查流程

1. **看是否有 `default-src`**：有它则所有取源类指令都有兜底，没写具体指令不代表没限制。
2. **单独确认 4 个不回退的指令**：`frame-ancestors`、`form-action`、`base-uri`、`sandbox`——漏写即为不限制。
3. **搜违规关键字**：出现 `'unsafe-inline'` / `'unsafe-eval'` / `https:` / `*` 说明这一项实际上很宽，不要误判为已加固。
4. **区分指令的作用面**：`script-src` 同时管内联与外部；`script-src-attr` 只管事件属性；`style-src` 同时管 `<style>` 与 `style="..."`。
5. **看内联是否已 nonce/hash 化**：有 nonce/hash 时 `'unsafe-inline'` 会被忽略。
6. **注意继承**：`srcdoc` / `about:blank` / `blob:` 文档**继承父文档 CSP**——iframe 预览白屏常是这个原因。
7. **报错归因**：CSP 违规报 `Refused to ... violates CSP`；CORS 报缺 `Access-Control-Allow-Origin`。两者是独立闸门，都要过。
8. **上线路径**：先 `Report-Only` 跑 1–2 周收敛误报 → 切强制 → 移除 `'unsafe-inline'` / `'unsafe-eval'`。

---

## 六、最小推荐基线

```http
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-<每次响应随机>' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
  frame-ancestors 'none';
  form-action 'self';
  upgrade-insecure-requests
```

`object-src 'none'`、`base-uri 'none'`、`frame-ancestors 'none'` 三项成本极低、收益明确，几乎所有站点都该加。
