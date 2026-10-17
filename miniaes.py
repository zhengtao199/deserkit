# -*- coding: utf-8 -*-
"""
纯 Python AES 实现（无第三方依赖），支持 Shiro 所需的：
  · AES-128/192/256-CBC + PKCS7          aes_cbc_encrypt / aes_cbc_decrypt / pkcs7_pad
  · 单块 ECB（GCM 的内部积木）            aes_ecb_encrypt_block
  · AES-GCM（Shiro ≥1.5.3 的 GCM 模式）   aes_gcm_encrypt / aes_gcm_decrypt

GCM 输出布局与 Shiro 一致：base64(IV || CT || TAG)，IV 默认 16 字节随机，TAG 16 字节。
"""

def _gen_sbox():
    """按 GF(2^8) 求逆 + 仿射变换生成标准 AES S-box（避免手抄出错）"""
    sbox = bytearray(256)
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)   # p *= 3
        q ^= (q << 1) & 0xFF                                    # q /= 3
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        if q & 0x80:
            q ^= 0x09
        q &= 0xFF
        x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) \
              ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return bytes(sbox)


_SBOX = _gen_sbox()
assert _SBOX[:6] == bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B]), _SBOX[:6].hex()
assert _SBOX[0x53] == 0xED and _SBOX[0xFF] == 0x16
_INV_SBOX = bytearray(256)
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_INV_SBOX = bytes(_INV_SBOX)
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d)


def _mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _expand_key(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [bytearray(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = bytearray(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = bytearray(_SBOX[b] for b in t)
            t[0] ^= _RCON[(i // nk) - 1]
        elif nk > 6 and i % nk == 4:
            t = bytearray(_SBOX[b] for b in t)
        w.append(bytearray(w[i - nk][j] ^ t[j] for j in range(4)))
    return w, nr


def _encrypt_block(block, w, nr):
    s = [bytearray(4) for _ in range(4)]
    for i in range(16):
        s[i % 4][i // 4] = block[i]
    for r in range(4):
        for c in range(4):
            s[r][c] ^= w[c][r]
    for rnd in range(1, nr + 1):
        for r in range(4):
            for c in range(4):
                s[r][c] = _SBOX[s[r][c]]
        for r in range(1, 4):
            row = [s[r][(c + r) % 4] for c in range(4)]
            for c in range(4):
                s[r][c] = row[c]
        if rnd != nr:
            for c in range(4):
                a = [s[0][c], s[1][c], s[2][c], s[3][c]]
                s[0][c] = _mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3]
                s[1][c] = a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3]
                s[2][c] = a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3)
                s[3][c] = _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)
        for r in range(4):
            for c in range(4):
                s[r][c] ^= w[rnd * 4 + c][r]
    out = bytearray(16)
    for i in range(16):
        out[i] = s[i % 4][i // 4]
    return bytes(out)


def _decrypt_block(block, w, nr):
    s = [bytearray(4) for _ in range(4)]
    for i in range(16):
        s[i % 4][i // 4] = block[i]
    for r in range(4):
        for c in range(4):
            s[r][c] ^= w[nr * 4 + c][r]
    for rnd in range(nr - 1, -1, -1):
        for r in range(1, 4):
            row = [s[r][(c - r) % 4] for c in range(4)]
            for c in range(4):
                s[r][c] = row[c]
        for r in range(4):
            for c in range(4):
                s[r][c] = _INV_SBOX[s[r][c]]
        for r in range(4):
            for c in range(4):
                s[r][c] ^= w[rnd * 4 + c][r]
        if rnd != 0:
            for c in range(4):
                a = [s[0][c], s[1][c], s[2][c], s[3][c]]
                s[0][c] = _mul(a[0], 14) ^ _mul(a[1], 11) ^ _mul(a[2], 13) ^ _mul(a[3], 9)
                s[1][c] = _mul(a[0], 9) ^ _mul(a[1], 14) ^ _mul(a[2], 11) ^ _mul(a[3], 13)
                s[2][c] = _mul(a[0], 13) ^ _mul(a[1], 9) ^ _mul(a[2], 14) ^ _mul(a[3], 11)
                s[3][c] = _mul(a[0], 11) ^ _mul(a[1], 13) ^ _mul(a[2], 9) ^ _mul(a[3], 14)
    out = bytearray(16)
    for i in range(16):
        out[i] = s[i % 4][i // 4]
    return bytes(out)


def pkcs7_pad(data):
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def pkcs7_unpad(data):
    if not data or len(data) % 16:
        return data
    n = data[-1]
    if 1 <= n <= 16 and data[-n:] == bytes([n]) * n:
        return data[:-n]
    return data


def _cbc(data, key, iv, enc=True):
    w, nr = _expand_key(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        if enc:
            x = bytes(a ^ b for a, b in zip(blk, prev))
            c = _encrypt_block(x, w, nr)
            out += c
            prev = c
        else:
            d = _decrypt_block(blk, w, nr)
            out += bytes(a ^ b for a, b in zip(d, prev))
            prev = blk
    return bytes(out)


def aes_cbc_encrypt(key, iv, data):
    return _cbc(pkcs7_pad(data), key, iv, True)


def aes_cbc_decrypt(key, iv, data):
    return pkcs7_unpad(_cbc(data, key, iv, False))


# ============================================================
# GCM —— Shiro ≥1.5.3 的 AesGcmCipherService：base64(IV || CT || TAG)
# ============================================================
_GCM_R = (0xE1 << 120)          # 约简多项式 11100001 || 0^120


def _check_key(key):
    """AES 只接受 16/24/32 字节密钥。"""
    if len(key) not in (16, 24, 32):
        raise ValueError("AES 密钥必须是 16/24/32 字节，实际 %d 字节" % len(key))


def aes_ecb_encrypt_block(key, block16):
    """单块 AES 加密（ECB）。GCM 内部算 H / J0 / CTR 密钥流都靠它。

    Args:
        key: 16/24/32 字节密钥
        block16: 恰好 16 字节的明文块
    Returns:
        bytes: 16 字节密文块
    """
    _check_key(key)
    if len(block16) != 16:
        raise ValueError("block16 必须是 16 字节，实际 %d 字节" % len(block16))
    w, nr = _expand_key(key)
    return _encrypt_block(bytes(block16), w, nr)


def _gmul(x, y):
    """GHASH 的 GF(2^128) 乘法（位反射实现）。

    GCM 规范里 bit0 = 字节 0 的最高位，所以把块当大端整数时，
    bit0 落在整数的最高位(第 127 位)，移位方向为“向低位移动”。
    """
    xi = int.from_bytes(x, "big")
    z = 0
    v = int.from_bytes(y, "big")
    for j in range(127, -1, -1):            # 从 bit0 扫到 bit127
        if (xi >> j) & 1:
            z ^= v
        if v & 1:                           # 移出的低位为 1 → 异或约简多项式
            v = (v >> 1) ^ _GCM_R
        else:
            v >>= 1
    return z.to_bytes(16, "big")


def _pad16(data):
    """把数据补零到 16 字节的整数倍。"""
    return bytes(data) + b"\x00" * ((-len(data)) % 16)


def _ghash(h, data):
    """GHASH_H(X)：Y0=0，Yi=(Y{i-1} XOR Xi)·H。data 必须已补到 16 的倍数。"""
    y = b"\x00" * 16
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        y = _gmul(bytes(a ^ b for a, b in zip(y, blk)), h)
    return y


def _gcm_j0(h, iv):
    """算 J0：IV 为 12 字节时 J0 = IV || 0^31 || 1，否则走 GHASH 派生。"""
    iv = bytes(iv)
    if len(iv) == 12:
        return iv + b"\x00\x00\x00\x01"
    return _ghash(h, _pad16(iv) + b"\x00" * 8 + (len(iv) * 8).to_bytes(8, "big"))


def _inc32(block):
    """GCM 计数器递增：只对最后 32 位做 mod 2^32 加一。"""
    b = bytearray(block)
    n = int.from_bytes(b[12:16], "big")
    b[12:16] = ((n + 1) & 0xFFFFFFFF).to_bytes(4, "big")
    return bytes(b)


def _ctr(w, nr, icb, data):
    """GCM 内部的 CTR 模式（加解密同一个函数）。"""
    out = bytearray()
    cb = icb
    for i in range(0, len(data), 16):
        ks = _encrypt_block(cb, w, nr)
        blk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(blk, ks))
        cb = _inc32(cb)
    return bytes(out)


def _gcm_tag(w, nr, h, j0, aad, ct):
    """tag = AES_K(J0) XOR GHASH(AAD||pad || CT||pad || len(A)64 || len(C)64)"""
    s = _ghash(h, _pad16(aad) + _pad16(ct)
               + (len(aad) * 8).to_bytes(8, "big")
               + (len(ct) * 8).to_bytes(8, "big"))
    e = _encrypt_block(j0, w, nr)
    return bytes(a ^ b for a, b in zip(e, s))


def _ct_eq(a, b):
    """定长内容的常数时间比较（避免把 tag 比较写成短路 == 的坏习惯）。"""
    if len(a) != len(b):
        return False
    d = 0
    for x, y in zip(a, b):
        d |= x ^ y
    return d == 0


def aes_gcm_encrypt(key, iv, plaintext, aad=b""):
    """标准 AES-GCM 加密（tag 固定 128 bit）。

    Args:
        key: 16/24/32 字节密钥
        iv: IV，12 字节走 J0=IV||0^31||1，其它长度（如 Shiro 的 16 字节）走 GHASH 派生
        plaintext: 明文（任意长度，GCM 不需要填充）
        aad: 附加认证数据
    Returns:
        (ct_bytes, tag_bytes)：密文与 16 字节 tag
    """
    _check_key(key)
    w, nr = _expand_key(key)
    h = _encrypt_block(b"\x00" * 16, w, nr)
    j0 = _gcm_j0(h, iv)
    ct = _ctr(w, nr, _inc32(j0), bytes(plaintext))
    return ct, _gcm_tag(w, nr, h, j0, bytes(aad), ct)


def aes_gcm_decrypt(key, iv, ct, tag, aad=b""):
    """标准 AES-GCM 解密：先校验 tag，校验失败返回 None（不抛异常）。

    Args:
        key: 16/24/32 字节密钥
        iv: 与加密时相同的 IV
        ct: 密文
        tag: 16 字节 tag
        aad: 附加认证数据
    Returns:
        bytes | None: 校验通过返回明文，否则 None
    """
    _check_key(key)
    w, nr = _expand_key(key)
    h = _encrypt_block(b"\x00" * 16, w, nr)
    j0 = _gcm_j0(h, iv)
    if not _ct_eq(bytes(tag), _gcm_tag(w, nr, h, j0, bytes(aad), bytes(ct))):
        return None
    return _ctr(w, nr, _inc32(j0), bytes(ct))


if __name__ == "__main__":
    # FIPS-197 AES-128-CBC 向量自检
    k = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    p = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    c = aes_cbc_encrypt(k, iv, p)          # 16 字节明文 + PKCS7 填充 → 32 字节
    assert c[:16].hex() == "7649abac8119b246cee98e9b12e9197d", c[:16].hex()
    assert aes_cbc_decrypt(k, iv, c) == p
    # AES-256-CBC 往返校验
    k2 = bytes(range(32))
    iv2 = bytes(range(16))
    assert aes_cbc_decrypt(k2, iv2, aes_cbc_encrypt(k2, iv2, b"hello shiro" * 3)) == b"hello shiro" * 3
    print("AES-128/256-CBC self-test OK")

    # ---- GCM 自检 ----
    # 单块 ECB 向量（FIPS-197 C.1）：key=000102…0f, pt=00112233…eeff
    assert aes_ecb_encrypt_block(bytes(range(16)),
                                 bytes.fromhex("00112233445566778899aabbccddeeff")).hex() \
        == "69c4e0d86a7b0430d8cdb78070b4c55a"
    # GCM 的 H = AES_K(0^128)，全 0 密钥下应等于 NIST 给的 66e94bd4…
    assert aes_ecb_encrypt_block(b"\x00" * 16, b"\x00" * 16).hex() \
        == "66e94bd4ef8a2c3b884cfa59ca342b2e"
    k0 = b"\x00" * 16                            # NIST GCM 向量用的是全 0 密钥
    # 空明文 + 空 AAD（NIST test case 1）：tag = AES_K(IV||0^31||1)
    ct1, tg1 = aes_gcm_encrypt(k0, b"\x00" * 12, b"", b"")
    assert ct1 == b"" and tg1.hex() == "58e2fccefa7e3061367f1d57a4e7455a", tg1.hex()
    assert aes_gcm_decrypt(k0, b"\x00" * 12, ct1, tg1, b"") == b""
    # 16 字节全 0 明文（NIST test case 2）
    ct2, tg2 = aes_gcm_encrypt(k0, b"\x00" * 12, b"\x00" * 16)
    assert ct2.hex() == "0388dace60b6a392f328c2b971b2fe78", ct2.hex()
    assert tg2.hex() == "ab6e47d42cec13bdf53a67b21257bddf", tg2.hex()
    assert aes_gcm_decrypt(k0, b"\x00" * 12, ct2, tg2) == b"\x00" * 16
    # 64 字节明文（NIST test case 3，4 个块，检验 GHASH 的多块迭代）
    k3 = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
    p3 = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                       "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
    ct3, tg3 = aes_gcm_encrypt(k3, bytes.fromhex("cafebabefacedbaddecaf888"), p3)
    assert ct3.hex() == ("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12"
                         "e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"), ct3.hex()
    assert tg3.hex() == "4d5c2af327cd64a62cf35abd2ba6fab4", tg3.hex()
    assert aes_gcm_decrypt(k3, bytes.fromhex("cafebabefacedbaddecaf888"), ct3, tg3) == p3
    # 带 AAD 的长报文（NIST test case 4）
    k4 = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
    iv4 = bytes.fromhex("cafebabefacedbaddecaf888")
    a4 = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    p4 = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                       "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
    ct4, tg4 = aes_gcm_encrypt(k4, iv4, p4, a4)
    assert tg4.hex() == "5bc94fbc3221a5db94fae95ae7121a47", tg4.hex()
    assert aes_gcm_decrypt(k4, iv4, ct4, tg4, a4) == p4
    # Shiro 场景：16 字节 IV（走 GHASH 派生 J0）+ 长报文，往返自洽
    k5 = b"GZCTFShiroGCMKey"                # 16 字节 ASCII 密钥
    iv5 = bytes(range(16))
    msg = b"\xac\xed\x00\x05" + b"ysoserial-payload" * 30
    ct5, tg5 = aes_gcm_encrypt(k5, iv5, msg)
    assert len(ct5) == len(msg) and len(tg5) == 16
    assert aes_gcm_decrypt(k5, iv5, ct5, tg5) == msg
    # 篡改检测：改 1 字节密文 → tag 校验失败返回 None
    bad = bytearray(ct5)
    bad[3] ^= 0x01
    assert aes_gcm_decrypt(k5, iv5, bytes(bad), tg5) is None
    # 篡改检测：改 1 字节 tag / AAD 不一致 → 同样失败
    btag = bytearray(tg5)
    btag[0] ^= 0x80
    assert aes_gcm_decrypt(k5, iv5, ct5, bytes(btag)) is None
    assert aes_gcm_decrypt(k5, iv5, ct5, tg5, b"X") is None
    print("AES-GCM self-test OK (NIST case 1/2/4 + 16B-IV 往返 + 篡改检测)")
