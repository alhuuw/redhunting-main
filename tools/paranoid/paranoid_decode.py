#!/usr/bin/env python3
"""Paranoid string deobfuscator port (byte-exact from smali) for the bukuwarung engagement.
Decodes io.michaelrocks.paranoid.Deobfuscator$* strings offline.

Usage: python3 paranoid_decode.py <DeobfuscatorClass.java> <key1> [key2 ...]
"""
import re
import sys

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1
MAX_CHUNK = 8191


def to_short(x):
    x &= 0xFFFF
    return x - 0x10000 if x >= 0x8000 else x


def sign64(s16):
    """Java (long) short cast — sign-extend 16-bit to 64-bit pattern."""
    v = s16 & 0xFFFF
    if v & 0x8000:
        v |= 0xFFFFFFFFFFFF0000
    return v & M64


def rotl_short(s, i):
    """Java (short)((s >>> (32-i)) | (s << i)) with s promoted to int (sign-extended)."""
    u = s & 0xFFFFFFFF  # sign-extended 32-bit pattern
    r = ((u >> (32 - i)) | ((u << i) & M32)) & M32
    return to_short(r)


def next64(j):
    j &= M64
    s10 = to_short(j & 0xFFFF)
    s11 = to_short((j >> 16) & 0xFFFF)
    s_rotl = to_short(rotl_short(to_short(s10 + s11), 9) + s10)
    s12 = to_short(s11 ^ s10)
    v0 = to_short(to_short(rotl_short(s10, 13) ^ s12) ^ (s12 << 5))
    p0 = sign64(rotl_short(s12, 10))
    v1 = (sign64(s_rotl) << 16) & M64
    p0 = (p0 | v1) & M64
    p0 = (p0 << 16) & M64
    p0 = (p0 | sign64(v0)) & M64
    return p0


def seed64(j):
    j &= M64
    j10 = ((j ^ (j >> 33)) * 7109453100751455733) & M64
    v = ((j10 ^ (j10 >> 28)) * ((-3808689974395783757) & M64)) & M64
    return (v >> 32) & M64


class Deob:
    def __init__(self, java_path):
        src = open(java_path).read()
        m = re.search(r'chunks = \{(.*?)\};', src, re.S)
        lits = re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1))
        self.chunks = [self._unesc(l) for l in lits]

    @staticmethod
    def _unesc(s):
        out, i = [], 0
        while i < len(s):
            if s[i] == '\\' and i + 1 < len(s):
                c = s[i + 1]
                if c == 'u':
                    out.append(chr(int(s[i + 2:i + 6], 16)))
                    i += 6
                    continue
                out.append({'n': '\n', 'r': '\r', 't': '\t', '\\': '\\', '"': '"', '0': '\0'}.get(c, c))
                i += 2
            else:
                out.append(s[i])
                i += 1
        return ''.join(out)

    def get_char_at(self, i, j):
        c = ord(self.chunks[i // MAX_CHUNK][i % MAX_CHUNK])
        n = next64(j)
        return ((c << 32) ^ n) & M64

    def get_string(self, j):
        j &= M64
        nxt = next64(seed64(j & 0xFFFFFFFF))
        j10 = (nxt >> 32) & 0xFFFF
        next2 = next64(nxt)
        i8 = (((j >> 32) & M32) ^ j10 ^ ((next2 >> 16) & 0xFFFF0000)) & M32
        char_at = self.get_char_at(i8, next2)
        ln = (char_at >> 32) & 0xFFFF
        out = []
        for k in range(ln):
            char_at = self.get_char_at(i8 + k + 1, char_at)
            out.append(chr((char_at >> 32) & 0xFFFF))
        return ''.join(out)


if __name__ == '__main__':
    path, keys = sys.argv[1], [int(x) for x in sys.argv[2:]]
    d = Deob(path)
    print('chunks:', len(d.chunks), [len(c) for c in d.chunks], file=sys.stderr)
    for k in keys:
        try:
            print(f'{k} => {d.get_string(k)!r}')
        except Exception as e:
            print(f'{k} => ERR {e}')
