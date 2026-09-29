# OAuth 2.0 实验台

两个脚本，两个用途，**别混用**。

| 脚本 | 定位 | 特征 |
|---|---|---|
| **`oauth_flow.py`** | 通用 OAuth 链路测试仪 | 能扫、能试、诊断详细，反复用 |
| **`deliver.py`** | 本题 exp | 一条命令跑完，参数少，不折腾 |

---

## 一分钟上手

### 1. 填配置

把 Cookie 抄进 `config.json`：

1. 浏览器登录平台
2. `F12` → **Application** → **Cookies**
3. 抄成一行，形如 `session=xxxxx`

必须对的四项：

| 字段 | 说明 |
|---|---|
| `client_id` / `client_secret` | 注册应用时平台给的 |
| `redirect_uri` | ★ **和注册时填的一字不差，原样照抄**，**别补域名** |
| `cookie` | 上面抄的 |

平台地址有默认值，不用填。

### 2. 先验证链路通不通

```bash
python oauth_flow.py --dry-run -v
```

**看到 `Location` 里有 `code=` 就成了。** 没有就先看下面的排错表。

### 3. 跑 exp

```bash
python deliver.py --scope profile.private
```

就这一条。`--scope` 不填会用 `config.json` 里的默认值。

> 具体可用的参数以各自的 `--help` 为准。

---

## 核心认知（理解这个，整道题就清楚了）

> ### 授权码是发给「访问这个链接的人」的。

同一串 authorize URL，**谁去访问，就决定了 token 认谁**：

```
你的脚本去访问   →  授权者 = 你自己   →  token 认你自己
官方去访问       →  授权者 = 官方     →  ★ token 认官方
```

而「官方去访问」这件事，平台自己给了你通道：**把链接私信给官方账号，它会登录试用。**

于是 exp 的全部工作就三件事：

```
1. 生成 authorize URL（带唯一 state）
2. 私信给官方
3. 等官方授权 → 从开放平台页捞出新出现的授权码 → 兑换 → 敲 /api/me
```

### 注意：这中间没有任何校验被绕过

`redirect_uri` 是我们自己登记过的地址，**合法**；`client_id` / `client_secret` 也是我们自己的。

真正起作用的是**「谁去访问」**——官方带着它自己的登录态访问，平台就为**官方**签发了授权码，而这个码**合法地落在了我们自己登记的回调上**。

---

## `oauth_flow.py` —— 测试仪

用来摸清链路、验证猜想、批量试 `scope`。

**它自己访问链接，所以授权者是你自己。** 这是它和 exp 的根本区别。

### 三种用法

```bash
# 1) 只跑第 1~3 棒：验证 Cookie 和回调通不通
python oauth_flow.py --dry-run -v

# 2) 跑完整流程（自己授权），把 token 打出来
python oauth_flow.py --scope profile

# 3) 批量试一串 scope，出一张对照表
python oauth_flow.py --scope-file scopes.example.txt --json-out result.json
```

### 输出怎么读

重点永远是这两行：

```
  请求的 scope: profile.private
  签发的 scope: profile
```

> **一律以「签发的」为准。** 平台可以静默过滤、可以降级 —— 你申请什么，不代表你拿到什么。

如果拿到 token 但接口权限不够，看 `WWW-Authenticate` 头：

```
WWW-Authenticate: Bearer error="insufficient_scope", scope="profile.private"
                                                        ↑ 这常常就是你要的名字
```

**这是免费情报，重点看它。**

### 常用参数

| 参数 | 说明 |
|---|---|
| `--dry-run` | 只跑第 1~3 棒就停 |
| `--scope` / `--scopes` / `--scope-file` | 单个 / 逗号分隔 / 文件，逐个试 |
| `--api-path` | 可重复，默认 `/api/me` |
| `--auth-style body\|basic` | `client_secret` 放哪（报 `invalid_client` 时换一种试） |
| `--prompt` | 如 `none` —— 试探能否跳过同意那一屏 |
| `-v` | 打印每一条请求和响应 |
| `--json-out` | 结果写成 JSON |

---

## `deliver.py` —— 本题 exp

```bash
python deliver.py --scope profile.private            # 真投递
python deliver.py --scope profile.private --dry-run  # 只看要发出去的 URL
```

### 为什么它用「集合差集」而不是「取最新的」

开放平台页会**累积列出所有历史授权码**，里面还混着干扰项。所以「最新」≠「我这次要的」。

exp 的做法：

```
投递前 → 把页面上已有的 code 全记成一个集合（基线）
投递后 → 轮询，等一个「不在集合里」的 code 出现
                ↑ 新出现的那个，必然是官方这次授权产生的
```

**这不是排序取尾，是前后做差。** 天然免疫竞态和干扰项 —— 这也才是「怎么拿到这次的 code」这个问题的正解。

### 为什么它自包含

exp **不 import 测试仪**。

理由：测试仪是要反复改的，exp 是一次性的。耦合在一起，重构测试仪就可能把 exp 弄坏。所以哪怕多抄几十行辅助函数，也换「改测试仪绝不影响 exp」。

代价是 `redirect_uri` 的一致性逻辑写了两遍。用**约定**消掉：两边都从同一个 `config.json` 读，且**都不加工它**。

---

## 排错表

### 第 1 棒（authorize）

| 现象 | 含义 | 怎么办 |
|---|---|---|
| `302 → /login` | **Cookie 失效 / 未登录** | 重新抄 Cookie |
| `200` + 含 `<form>` | 拿到登录页 | 同上 |
| `302` 到同意页 | 需要人工点一次同意 | 试 `--prompt none` |
| `400` 地址不合法 | `redirect_uri` 和登记的不一致 | 一字不差照抄 |
| `403` | 应用未上线 / 不在测试名单 / scope 未获批 | 去后台看应用状态 |

### 第 4 棒（token）

| `error=` | 查什么 |
|---|---|
| `invalid_grant` | ① code 用过/过期 ② **`redirect_uri` 两次不一致** ③ 跨客户端 ④ 缺 PKCE 的 verifier |
| `invalid_client` | 公章 / 客户端身份。试 `--auth-style basic`，查 secret 首尾空格 |
| `invalid_scope` | **这个 scope 名不被接受** —— 对批量扫描来说，这是一条「名字不存在」的结论 |
| `invalid_request` | 格式：`Content-Type`、参数放 body 里、`grant_type` 拼写 |

### 第 5 棒（API）

| 现象 | 含义 |
|---|---|
| `401 invalid_token` | token 无效 / 过期 / 撤销 |
| `403 insufficient_scope` | **token 有效但权限不够** —— 看 `WWW-Authenticate` 里的 `scope="..."` |

### exp 专属

| 现象 | 含义 | 怎么办 |
|---|---|---|
| 私信后一直没新 code | 官方没访问 / 点了拒绝 / 应用未上线 | **先手工**在浏览器发一次私信，确认官方到底会不会响应 |
| 提取不到授权码 | 页面结构变了 | 把页面存下来看真实 markup |
| 拿到的 token 是你自己 | 官方没授权，你拿到的是自己那条 | 看开放平台页上是不是真多了一个 code |

---

## 三个不能踩的坑

| 坑 | 说明 |
|---|---|
| **手工"规范化" `redirect_uri`** | 平台给的是相对路径 `/oauth/cb/xxx`，**别自己补域名**。第 1 棒和第 4 棒必须用**同一个字符串** —— 这是 `invalid_grant` 的头号成因 |
| **复用旧 code** | code 一次性、几十秒过期。别把历史 code 写死进脚本 |
| **只看"申请的 scope"** | 一律以**签发的**为准 |

---

## 扫 scope 的顺序

批量试是**最后一步**，别一上来就瞎猜。前三步是「知道名字从哪来、要什么」：

1. **抓平台自己的官方应用在申请什么 scope** —— 它自己的网页版 / App 也是一个 OAuth 客户端，抓它的 `/oauth/authorize` 请求。**官方客户端必然申请了能读私密资料的权限。**
2. **敲 `.well-known/openid-configuration`** —— 如果平台吃 OIDC，`scopes_supported` 就是平台自己交出来的清单。
3. **用已知有效的 token 去敲那个「私密资料」接口**，读它返回的 `insufficient_scope` / `required_scope`。
4. **最后**才用 `oauth_flow.py --scope-file` 批量验证（候选见 `scopes.example.txt`）。

---

## 实测记录

对 `http://172.17.0.13:15633` 的实际观察：

| 项目 | 结果 |
|---|---|
| 站点地图 | `/` 主页、`/dev` 开放平台、`/dm` 私信、`/register` 注册、`/login` 登录 |
| 会话 Cookie 名 | `session`（Flask session；**登录成功才下发**，失败登录不发 `Set-Cookie`） |
| `GET /oauth/authorize`（不带 Cookie） | `302 → /login` |
| `GET /oauth/authorize`（跟随重定向） | `200`，标题「登录 — 社交平台」 |
| `GET /api/me`（不带 token） | `401 {"error":"invalid_token"}` |
| `/dev` | 显示 client_id / client_secret / redirect_uri，以及**「已收到的授权码」列表** |

**两条结论：**

1. **未登录时平台返回 `302 → /login`**（不是直接给登录页）。所以脚本必须**不跟随重定向**才能看到这个信号 —— 跟了就只能看到 200 的登录页，反而看不出问题在哪。
2. `redirect_uri` 在本题是**相对路径**（`/oauth/cb/app_xxx`），照抄，**不要补域名**。

> 附带一提：Flask session 是**签名但不加密**的 —— payload 是 base64 + zlib 压缩的 JSON，可以直接解出来看。签名保证你改不了，但**不保证内容保密**。
