"""
Demo 3 mô hình áp dụng RSA:
  1. Bảo mật / xác thực người nhận : mã hoá bằng khoá CÔNG KHAI của người nhận
  2. Xác thực người gửi (chữ ký số) : ký bằng khoá BÍ MẬT của người gửi
  3. Kết hợp cả hai                 : ký + mã hoá
"""
import my_rsa as rsa

BITS = 1024  # demo cho nhanh; thực tế dùng >= 2048


def title(s):
    print("\n" + "=" * 70 + f"\n{s}\n" + "=" * 70)


def main():
    print(f"Sinh khoá RSA-{BITS} cho Alice (người gửi), Bob (người nhận), Eve (kẻ tấn công)...")
    alice_pub, alice_priv = rsa.generate_keypair(BITS)
    bob_pub, bob_priv = rsa.generate_keypair(BITS)
    eve_pub, eve_priv = rsa.generate_keypair(BITS)

    msg = "Chuyen 100 trieu cho Bob".encode()

    # ------------------------------------------------------------------
    title("MÔ HÌNH 1: Xác thực người nhận (bảo mật)   C = E(PU_Bob, M)")
    c = rsa.encrypt(bob_pub, msg)
    print("Alice mã hoá bằng khoá công khai của Bob ->", c.hex()[:48], "...")
    print("Bob giải mã bằng khoá bí mật của mình  ->", rsa.decrypt(bob_priv, c).decode())
    try:
        print("Eve thử giải mã bằng khoá của Eve      ->", rsa.decrypt(eve_priv, c))
    except ValueError as ex:
        print("Eve thử giải mã bằng khoá của Eve      -> THẤT BẠI:", ex)
    print("=> Chỉ người giữ khoá bí mật của Bob đọc được. Nhưng Bob KHÔNG biết ai gửi"
          " (bất kỳ ai cũng có khoá công khai của Bob).")

    # ------------------------------------------------------------------
    title("MÔ HÌNH 2: Xác thực người gửi (chữ ký số)   S = Sign(PR_Alice, H(M))")
    sig = rsa.sign(alice_priv, msg)
    print("Alice ký bằng khoá bí mật của mình     ->", sig.hex()[:48], "...")
    print("Bob xác minh bằng khoá công khai Alice ->", rsa.verify(alice_pub, msg, sig))
    print("Thông điệp bị sửa (100 -> 900 trieu)    ->",
          rsa.verify(alice_pub, b"Chuyen 900 trieu cho Bob", sig))
    print("Eve giả mạo chữ ký bằng khoá của Eve   ->",
          rsa.verify(alice_pub, msg, rsa.sign(eve_priv, msg)))
    print("=> Xác thực người gửi + toàn vẹn + chống chối bỏ. Nhưng thông điệp KHÔNG được giữ bí mật.")

    # ------------------------------------------------------------------
    title("MÔ HÌNH 3: Kết hợp cả hai  (ký bằng PR_Alice, mã hoá bằng PU_Bob)")
    sig = rsa.sign(alice_priv, msg)          # xác thực người gửi
    c = rsa.encrypt(bob_pub, msg)            # bảo mật / xác thực người nhận
    print("Alice gửi (C, S) gồm bản mã và chữ ký")
    m2 = rsa.decrypt(bob_priv, c)            # Bob giải mã
    ok = rsa.verify(alice_pub, m2, sig)      # Bob kiểm tra chữ ký
    print("Bob giải mã ->", m2.decode())
    print("Bob xác minh chữ ký của Alice ->", ok)
    print("=> Vừa bí mật, vừa xác thực người gửi, vừa toàn vẹn.")


if __name__ == "__main__":
    main()
