#!/usr/bin/env python3
# 作者奶瓶喵

import argparse
import base64
import binascii
import re
import struct
from urllib.parse import unquote, urlsplit

KEY = b"HjqxOZ3s3yNbtSw7"
MASK = 0xFFFFFFFF
DELTA = 0x9E3779B9


def extract_cipher(text):
    text = text.strip().strip("\"'")
    is_link = "://" in text
    if is_link:
        text = urlsplit(text).query
    match = re.search(r"(?:^|[?&])pwd=([^&\s#]+)", text)
    if match:
        text = match.group(1)
    elif is_link or "pwd=" in text:
        raise ValueError("链接中没有有效的 pwd 参数")
    text = unquote(text)
    return text + "=" * (-len(text) % 4)


def decrypt(text):
    try:
        data = base64.b64decode(extract_cipher(text), validate=True)
    except (binascii.Error, UnicodeError) as exc:
        raise ValueError("密文不是有效的 Base64") from exc
    if len(data) < 8 or len(data) % 4:
        raise ValueError("密文长度不正确")

    v = list(struct.unpack("<%dI" % (len(data) // 4), data))
    k = struct.unpack("<4I", KEY)
    n = len(v)
    total = ((6 + 52 // n) * DELTA) & MASK
    y = v[0]

    # XXTEA
    while total:
        e = (total >> 2) & 3
        for p in range(n - 1, -1, -1):
            z = v[p - 1 if p else n - 1]
            mx = (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4))
                  ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z))) & MASK
            v[p] = (v[p] - mx) & MASK
            y = v[p]
        total = (total - DELTA) & MASK

    length = v[-1]
    plain = struct.pack("<%dI" % (n - 1), *v[:-1])
    if not len(plain) - 3 <= length <= len(plain):
        raise ValueError("解密失败：密文或密钥不匹配")
    plain = plain[:length]
    if not plain or any(c < 48 or c > 57 for c in plain):
        raise ValueError("解密结果不是数字密码")
    return plain.decode("ascii")


def main():
    parser = argparse.ArgumentParser(description="KernelSU 入群验证解密 · 奶瓶制作")
    parser.add_argument("text", nargs="?", help="完整链接或 pwd 密文")
    args = parser.parse_args()
    print("KernelSU 入群验证解密 作者奶瓶喵")
    try:
        text = args.text if args.text is not None else input("粘贴链接或密文：")
        password = decrypt(text)
    except (ValueError, EOFError) as exc:
        print("错误：", exc)
        return 1
    except KeyboardInterrupt:
        print()
        return 130
    print("密码：", password)
    print("/join " + password)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
