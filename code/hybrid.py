"""
Mã hoá lai (Hybrid Encryption): AES mã hoá dữ liệu lớn, RSA bảo vệ khoá AES và ký.

Người gửi (Alice):
  1. Sinh khoá phiên AES-256 ngẫu nhiên (K)
  2. Mã hoá dữ liệu bằng AES-CBC(K)                 -> nhanh, không giới hạn độ dài
  3. Mã hoá K bằng khoá công khai RSA của Bob        -> chỉ Bob lấy được K
  4. Ký (IV||bản mã||K đã mã hoá) bằng khoá bí mật của Alice -> xác thực + toàn vẹn
Người nhận (Bob): kiểm tra chữ ký -> giải mã K bằng RSA -> giải mã dữ liệu bằng AES

Dùng:  python demo_hybrid.py                  (thông điệp mẫu)
       python demo_hybrid.py duong_dan_file   (mã hoá file bất kỳ)
"""
import base64
import json
import os
import sys

import my_aes as aes
import my_rsa as rsa


def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()


def unb64(x: str) -> bytes:
    return base64.b64decode(x)


def hybrid_encrypt(data: bytes, sender_priv, receiver_pub) -> dict:
    session_key = os.urandom(32)                                  # AES-256
    aes_blob = aes.cbc_encrypt(session_key, data)                 # IV || ciphertext
    enc_key = rsa.encrypt(receiver_pub, session_key)              # RSA bọc khoá phiên
    signature = rsa.sign(sender_priv, aes_blob + enc_key)         # ký lên toàn bộ gói
    return {"enc_key": b64(enc_key), "data": b64(aes_blob), "signature": b64(signature)}


def hybrid_decrypt(package: dict, receiver_priv, sender_pub) -> bytes:
    enc_key, blob, sig = unb64(package["enc_key"]), unb64(package["data"]), unb64(package["signature"])
    if not rsa.verify(sender_pub, blob + enc_key, sig):
        raise ValueError("Chữ ký không hợp lệ: gói tin bị sửa hoặc không phải của người gửi")
    session_key = rsa.decrypt(receiver_priv, enc_key)
    return aes.cbc_decrypt(session_key, blob)


def main():
    if len(sys.argv) > 1:
        with open(sys.argv[1], "rb") as f:
            data = f.read()
        print(f"Đọc file {sys.argv[1]} ({len(data)} byte)")
    else:
        data = ("Đây là dữ liệu dài. " * 500).encode()
        print(f"Dùng thông điệp mẫu ({len(data)} byte, dài hơn nhiều so với giới hạn của RSA)")

    print("Sinh khoá RSA-2048 cho Alice và Bob...")
    alice_pub, alice_priv = rsa.generate_keypair(2048)
    bob_pub, bob_priv = rsa.generate_keypair(2048)
    print(f"RSA-2048 chỉ mã hoá trực tiếp được tối đa {rsa.max_message_len(bob_pub)} byte/khối "
          f"-> dùng AES cho dữ liệu.\n")

    pkg = hybrid_encrypt(data, alice_priv, bob_pub)
    print("Gói tin gửi đi (JSON):")
    for k, v in pkg.items():
        print(f"  {k:<10}: {len(unb64(v))} byte  {v[:40]}...")
    with open("package.json", "w") as f:
        json.dump(pkg, f, indent=2)
    print("  (đã lưu vào package.json)")

    out = hybrid_decrypt(pkg, bob_priv, alice_pub)
    print("\nBob giải mã đúng dữ liệu gốc:", out == data)

    # Kẻ tấn công sửa 1 byte bản mã
    tampered = dict(pkg)
    blob = bytearray(unb64(pkg["data"]))
    blob[20] ^= 1
    tampered["data"] = b64(bytes(blob))
    try:
        hybrid_decrypt(tampered, bob_priv, alice_pub)
    except ValueError as ex:
        print("Gói tin bị sửa 1 bit  ->", ex)


if __name__ == "__main__":
    main()
