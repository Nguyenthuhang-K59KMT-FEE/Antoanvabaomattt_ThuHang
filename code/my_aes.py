"""
AES (Advanced Encryption Standard) - cài đặt từ đầu theo FIPS-197.

Hỗ trợ khoá 128 / 192 / 256 bit, chế độ CBC + đệm PKCS#7.
CHỈ DÙNG ĐỂ HỌC TẬP: không chống được tấn công kênh kề (timing, cache), chạy chậm.
Trong thực tế hãy dùng thư viện đã kiểm định (cryptography, OpenSSL...).

Quy ước trạng thái (state): danh sách 16 byte, xếp theo CỘT
    chỉ số = hàng + 4 * cột   (khớp với thứ tự byte của khối vào/ra)
"""
import os

# ----------------------------------------------------------------------------
# 1. Số học trường hữu hạn GF(2^8) với đa thức bất khả quy x^8 + x^4 + x^3 + x + 1
# ----------------------------------------------------------------------------


def _xtime(a: int) -> int:
    """Nhân với x (tức nhân 2) trong GF(2^8)."""
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a


def _gmul(a: int, b: int) -> int:
    """Nhân hai phần tử trong GF(2^8)."""
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _make_sbox():
    """S-box = nghịch đảo trong GF(2^8) rồi biến đổi affine (cộng 0x63)."""
    sbox = [0] * 256
    for x in range(256):
        inv = 0
        if x:
            inv = 1
            for _ in range(254):  # x^254 = x^-1 vì x^255 = 1
                inv = _gmul(inv, x)
        s = inv ^ _rotl8(inv, 1) ^ _rotl8(inv, 2) ^ _rotl8(inv, 3) ^ _rotl8(inv, 4) ^ 0x63
        sbox[x] = s
    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i
    return sbox, inv_sbox


SBOX, INV_SBOX = _make_sbox()

# Bảng nhân sẵn cho MixColumns / InvMixColumns (chạy nhanh hơn)
M2 = [_gmul(i, 2) for i in range(256)]
M3 = [_gmul(i, 3) for i in range(256)]
M9 = [_gmul(i, 9) for i in range(256)]
M11 = [_gmul(i, 11) for i in range(256)]
M13 = [_gmul(i, 13) for i in range(256)]
M14 = [_gmul(i, 14) for i in range(256)]

# ----------------------------------------------------------------------------
# 2. Bốn phép biến đổi của một vòng AES
# ----------------------------------------------------------------------------


def _sub_bytes(s):
    return [SBOX[b] for b in s]


def _inv_sub_bytes(s):
    return [INV_SBOX[b] for b in s]


def _shift_rows(s):
    """Hàng r dịch vòng trái r byte."""
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            out[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
    return out


def _inv_shift_rows(s):
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            out[r + 4 * ((c + r) % 4)] = s[r + 4 * c]
    return out


def _mix_columns(s):
    out = [0] * 16
    for c in range(0, 16, 4):
        a0, a1, a2, a3 = s[c:c + 4]
        out[c] = M2[a0] ^ M3[a1] ^ a2 ^ a3
        out[c + 1] = a0 ^ M2[a1] ^ M3[a2] ^ a3
        out[c + 2] = a0 ^ a1 ^ M2[a2] ^ M3[a3]
        out[c + 3] = M3[a0] ^ a1 ^ a2 ^ M2[a3]
    return out


def _inv_mix_columns(s):
    out = [0] * 16
    for c in range(0, 16, 4):
        a0, a1, a2, a3 = s[c:c + 4]
        out[c] = M14[a0] ^ M11[a1] ^ M13[a2] ^ M9[a3]
        out[c + 1] = M9[a0] ^ M14[a1] ^ M11[a2] ^ M13[a3]
        out[c + 2] = M13[a0] ^ M9[a1] ^ M14[a2] ^ M11[a3]
        out[c + 3] = M11[a0] ^ M13[a1] ^ M9[a2] ^ M14[a3]
    return out


def _add_round_key(s, rk):
    return [a ^ b for a, b in zip(s, rk)]


# ----------------------------------------------------------------------------
# 3. Mở rộng khoá (Key Expansion)
# ----------------------------------------------------------------------------


def expand_key(key: bytes):
    """Trả về danh sách (Nr + 1) khoá vòng, mỗi khoá 16 byte."""
    if len(key) not in (16, 24, 32):
        raise ValueError("Khoá AES phải dài 16, 24 hoặc 32 byte")
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = w[i - 1][:]
        if i % nk == 0:
            t = t[1:] + t[:1]              # RotWord
            t = [SBOX[b] for b in t]       # SubWord
            t[0] ^= rcon                   # cộng hằng số vòng
            rcon = _xtime(rcon)
        elif nk > 6 and i % nk == 4:       # chỉ AES-256
            t = [SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(nr + 1)]


# ----------------------------------------------------------------------------
# 4. Mã hoá / giải mã một khối 16 byte
# ----------------------------------------------------------------------------


class AES:
    def __init__(self, key: bytes):
        self.round_keys = expand_key(key)
        self.nr = len(self.round_keys) - 1

    def encrypt_block(self, block: bytes, verbose: bool = False) -> bytes:
        if len(block) != 16:
            raise ValueError("Khối phải dài 16 byte")
        show = (lambda name, st: print(f"  {name:<18}{bytes(st).hex()}")) if verbose else (lambda *_: None)
        s = list(block)
        show("input", s)
        s = _add_round_key(s, self.round_keys[0])
        show("round[0].k_sch", self.round_keys[0])
        show("round[0].start", s)
        for r in range(1, self.nr):
            s = _sub_bytes(s); show(f"round[{r}].s_box", s)
            s = _shift_rows(s); show(f"round[{r}].s_row", s)
            s = _mix_columns(s); show(f"round[{r}].m_col", s)
            s = _add_round_key(s, self.round_keys[r]); show(f"round[{r}].k_add", s)
        s = _sub_bytes(s)
        s = _shift_rows(s)                 # vòng cuối KHÔNG có MixColumns
        s = _add_round_key(s, self.round_keys[self.nr])
        show(f"round[{self.nr}].output", s)
        return bytes(s)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Khối phải dài 16 byte")
        s = _add_round_key(list(block), self.round_keys[self.nr])
        for r in range(self.nr - 1, 0, -1):
            s = _inv_shift_rows(s)
            s = _inv_sub_bytes(s)
            s = _add_round_key(s, self.round_keys[r])
            s = _inv_mix_columns(s)
        s = _inv_shift_rows(s)
        s = _inv_sub_bytes(s)
        s = _add_round_key(s, self.round_keys[0])
        return bytes(s)


# ----------------------------------------------------------------------------
# 5. Chế độ CBC + đệm PKCS#7
# ----------------------------------------------------------------------------


def pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    n = block - len(data) % block
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, block: int = 16) -> bytes:
    if not data or len(data) % block:
        raise ValueError("Độ dài dữ liệu không hợp lệ")
    n = data[-1]
    if n < 1 or n > block or data[-n:] != bytes([n]) * n:
        raise ValueError("Đệm PKCS#7 sai (sai khoá hoặc dữ liệu bị sửa)")
    return data[:-n]


def cbc_encrypt(key: bytes, plaintext: bytes, iv: bytes = None) -> bytes:
    """Trả về IV (16 byte) || bản mã."""
    iv = iv or os.urandom(16)
    aes = AES(key)
    data = pkcs7_pad(plaintext)
    prev, out = iv, [iv]
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = aes.encrypt_block(blk)
        out.append(prev)
    return b"".join(out)


def cbc_decrypt(key: bytes, data: bytes) -> bytes:
    """Nhận IV || bản mã, trả về bản rõ."""
    if len(data) < 32 or len(data) % 16:
        raise ValueError("Bản mã không hợp lệ")
    aes = AES(key)
    prev, out = data[:16], []
    for i in range(16, len(data), 16):
        blk = data[i:i + 16]
        out.append(bytes(a ^ b for a, b in zip(aes.decrypt_block(blk), prev)))
        prev = blk
    return pkcs7_unpad(b"".join(out))


if __name__ == "__main__":
    # Ví dụ trong FIPS-197 Appendix C.1 (AES-128), in ra từng bước
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    print("AES-128, plaintext =", pt.hex())
    ct = AES(key).encrypt_block(pt, verbose=True)
    print("ciphertext =", ct.hex(), "(mong đợi 69c4e0d86a7b0430d8cdb78070b4c55a)")
    print("decrypt    =", AES(key).decrypt_block(ct).hex())
