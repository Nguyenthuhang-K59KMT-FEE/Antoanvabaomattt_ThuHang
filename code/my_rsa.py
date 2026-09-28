"""
RSA cài đặt từ đầu: sinh khoá, mã hoá/giải mã, ký/xác minh.

Đệm: PKCS#1 v1.5 (kiểu 2 cho mã hoá, kiểu 1 + SHA-256 cho chữ ký).
CHỈ DÙNG ĐỂ HỌC TẬP. Thực tế hãy dùng RSA-OAEP / RSA-PSS từ thư viện đã kiểm định.
"""
import hashlib
import math
import secrets
from dataclasses import dataclass

# ----------------------------------------------------------------------------
# 1. Kiểm tra nguyên tố Miller-Rabin và sinh số nguyên tố
# ----------------------------------------------------------------------------

_SMALL_PRIMES = [p for p in range(2, 300) if all(p % d for d in range(2, int(p ** 0.5) + 1))]


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    # n - 1 = 2^s * d với d lẻ
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    while True:
        # đặt 2 bit cao để p*q chắc chắn đủ 2*bits bit; bit thấp = 1 để là số lẻ
        c = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if is_probable_prime(c):
            return c


# ----------------------------------------------------------------------------
# 2. Sinh cặp khoá
# ----------------------------------------------------------------------------


@dataclass
class PublicKey:
    n: int
    e: int

    @property
    def size(self) -> int:  # số byte của modulus
        return (self.n.bit_length() + 7) // 8


@dataclass
class PrivateKey:
    n: int
    d: int
    p: int
    q: int

    @property
    def size(self) -> int:
        return (self.n.bit_length() + 7) // 8

    # tham số CRT để giải mã nhanh hơn ~3-4 lần
    @property
    def dp(self): return self.d % (self.p - 1)

    @property
    def dq(self): return self.d % (self.q - 1)

    @property
    def qinv(self): return pow(self.q, -1, self.p)


def generate_keypair(bits: int = 2048, e: int = 65537):
    """
    1. Chọn 2 số nguyên tố lớn p != q
    2. n = p*q
    3. phi(n) = (p-1)(q-1)
    4. Chọn e: 1 < e < phi, gcd(e, phi) = 1     (thường e = 65537)
    5. d = e^-1 mod phi
    Khoá công khai (n, e); khoá bí mật (n, d)
    """
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) != 1:
            continue
        n = p * q
        d = pow(e, -1, phi)
        return PublicKey(n, e), PrivateKey(n, d, p, q)


# ----------------------------------------------------------------------------
# 3. Phép toán RSA thô: c = m^e mod n,  m = c^d mod n
# ----------------------------------------------------------------------------


def _public_op(pub: PublicKey, x: int) -> int:
    if not 0 <= x < pub.n:
        raise ValueError("Giá trị phải nhỏ hơn n")
    return pow(x, pub.e, pub.n)


def _private_op(priv: PrivateKey, x: int, use_crt: bool = True) -> int:
    if not 0 <= x < priv.n:
        raise ValueError("Giá trị phải nhỏ hơn n")
    if not use_crt:
        return pow(x, priv.d, priv.n)
    m1 = pow(x, priv.dp, priv.p)
    m2 = pow(x, priv.dq, priv.q)
    h = (priv.qinv * (m1 - m2)) % priv.p
    return m2 + h * priv.q


# ----------------------------------------------------------------------------
# 4. Mã hoá / giải mã (đệm PKCS#1 v1.5 kiểu 2)
# ----------------------------------------------------------------------------


def max_message_len(pub: PublicKey) -> int:
    return pub.size - 11


def encrypt(pub: PublicKey, message: bytes) -> bytes:
    k = pub.size
    if len(message) > k - 11:
        raise ValueError(f"Bản rõ quá dài: tối đa {k - 11} byte với khoá này")
    ps = bytes(secrets.choice(range(1, 256)) for _ in range(k - 3 - len(message)))
    em = b"\x00\x02" + ps + b"\x00" + message
    c = _public_op(pub, int.from_bytes(em, "big"))
    return c.to_bytes(k, "big")


def decrypt(priv: PrivateKey, ciphertext: bytes, use_crt: bool = True) -> bytes:
    k = priv.size
    if len(ciphertext) != k:
        raise ValueError("Độ dài bản mã sai")
    em = _private_op(priv, int.from_bytes(ciphertext, "big"), use_crt).to_bytes(k, "big")
    if em[0] != 0 or em[1] != 2 or 0 not in em[2:]:
        raise ValueError("Giải mã thất bại (sai khoá hoặc dữ liệu hỏng)")
    sep = em.index(0, 2)
    if sep < 10:
        raise ValueError("Giải mã thất bại (đệm sai)")
    return em[sep + 1:]


# ----------------------------------------------------------------------------
# 5. Ký / xác minh chữ ký (RSASSA-PKCS1-v1_5, SHA-256)
# ----------------------------------------------------------------------------

_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _emsa_pkcs1_v15(message: bytes, k: int) -> bytes:
    t = _SHA256_PREFIX + hashlib.sha256(message).digest()
    if k < len(t) + 11:
        raise ValueError("Khoá quá ngắn để ký SHA-256")
    return b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


def sign(priv: PrivateKey, message: bytes, use_crt: bool = True) -> bytes:
    """Chữ ký = (đệm(hash(m)))^d mod n -- ký lên HASH nên thông điệp dài bao nhiêu cũng được."""
    k = priv.size
    em = _emsa_pkcs1_v15(message, k)
    s = _private_op(priv, int.from_bytes(em, "big"), use_crt)
    return s.to_bytes(k, "big")


def verify(pub: PublicKey, message: bytes, signature: bytes) -> bool:
    k = pub.size
    if len(signature) != k:
        return False
    try:
        em = _public_op(pub, int.from_bytes(signature, "big")).to_bytes(k, "big")
        return secrets.compare_digest(em, _emsa_pkcs1_v15(message, k))
    except ValueError:
        return False


if __name__ == "__main__":
    # Ví dụ số nhỏ (chỉ minh hoạ toán học, KHÔNG an toàn)
    p, q, e = 61, 53, 17
    n, phi = p * q, (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = 65
    c = pow(m, e, n)
    print(f"p={p} q={q} n={n} phi={phi} e={e} d={d}")
    print(f"m={m} -> c=m^e mod n={c} -> m'=c^d mod n={pow(c, d, n)}")
