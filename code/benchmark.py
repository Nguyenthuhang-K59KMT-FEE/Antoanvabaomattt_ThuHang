"""
So sánh thời gian mã hoá / giải mã của AES và RSA.

Phần A: hai cài đặt tự viết (cùng là Python thuần -> so sánh tương đối công bằng)
Phần B: (tuỳ chọn) thư viện `cryptography` viết bằng C/OpenSSL -> gần với thực tế
        cài bằng:  pip install cryptography

Dùng:  python benchmark.py
"""
import os
import time

import my_aes as aes
import my_rsa as rsa

SIZES = [1024, 10 * 1024, 100 * 1024]  # byte


def best_time(fn, repeat=3):
    best = float("inf")
    for _ in range(repeat):
        t = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t)
    return best


def fmt(size):
    return f"{size // 1024} KB"


def rsa_encrypt_long(pub, data):
    step = rsa.max_message_len(pub)
    return [rsa.encrypt(pub, data[i:i + step]) for i in range(0, len(data), step)]


def rsa_decrypt_long(priv, blocks):
    return b"".join(rsa.decrypt(priv, b) for b in blocks)


def row(name, size, t_enc, t_dec):
    speed = size / 1024 / t_enc
    print(f"{name:<14}{fmt(size):>8}{t_enc * 1000:>14.2f}{t_dec * 1000:>14.2f}{speed:>12.1f}")


def part_a():
    print("\n=== A. Cài đặt tự viết (Python thuần) ===")
    print(f"{'Thuật toán':<14}{'Dữ liệu':>8}{'Mã hoá (ms)':>14}{'Giải mã (ms)':>14}{'MH KB/s':>12}")
    key = os.urandom(16)
    for size in SIZES:
        data = os.urandom(size)
        ct = aes.cbc_encrypt(key, data)
        row("AES-128-CBC", size, best_time(lambda: aes.cbc_encrypt(key, data)),
            best_time(lambda: aes.cbc_decrypt(key, ct)))

    for bits in (1024, 2048):
        t0 = time.perf_counter()
        pub, priv = rsa.generate_keypair(bits)
        print(f"-- RSA-{bits}: sinh khoá mất {time.perf_counter() - t0:.2f}s")
        for size in SIZES:
            data = os.urandom(size)
            blocks = rsa_encrypt_long(pub, data)
            row(f"RSA-{bits}", size, best_time(lambda: rsa_encrypt_long(pub, data), 2),
                best_time(lambda: rsa_decrypt_long(priv, blocks), 2))
        # 1 phép RSA đơn lẻ
        blk = rsa.encrypt(pub, b"x" * 32)
        t_pub = best_time(lambda: rsa.encrypt(pub, b"x" * 32), 5)
        t_prv = best_time(lambda: rsa.decrypt(priv, blk), 5)
        t_prv_nocrt = best_time(lambda: rsa.decrypt(priv, blk, use_crt=False), 3)
        print(f"   1 phép RSA-{bits}: dùng khoá công khai {t_pub * 1000:.3f} ms | "
              f"khoá bí mật (CRT) {t_prv * 1000:.3f} ms | khoá bí mật (không CRT) {t_prv_nocrt * 1000:.3f} ms")


def part_b():
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa as crsa
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        print("\n(Bỏ qua phần B: chưa cài thư viện `cryptography` -> pip install cryptography)")
        return

    print("\n=== B. Thư viện `cryptography` (OpenSSL, mã C) ===")
    print(f"{'Thuật toán':<14}{'Dữ liệu':>8}{'Mã hoá (ms)':>14}{'Giải mã (ms)':>14}{'MH KB/s':>12}")
    key, iv = os.urandom(16), os.urandom(16)
    for size in SIZES + [10 * 1024 * 1024]:
        data = os.urandom(size)

        def enc():
            e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
            return e.update(data) + e.finalize()

        ct = enc()

        def dec():
            d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            return d.update(ct) + d.finalize()

        row("AES-128-CBC", size, best_time(enc, 5), best_time(dec, 5))

    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    for bits in (2048, 4096):
        priv = crsa.generate_private_key(65537, bits)
        pub = priv.public_key()
        step = bits // 8 - 66
        for size in SIZES:
            data = os.urandom(size)
            chunks = [data[i:i + step] for i in range(0, size, step)]
            cts = [pub.encrypt(c, oaep) for c in chunks]
            row(f"RSA-{bits}", size, best_time(lambda: [pub.encrypt(c, oaep) for c in chunks]),
                best_time(lambda: [priv.decrypt(c, oaep) for c in cts], 2))


if __name__ == "__main__":
    part_a()
    part_b()
    print("\nLưu ý: kết quả phụ thuộc máy; hãy chạy trên máy của bạn để lấy số liệu báo cáo.")
