from Crypto.Cipher import AES
import base64

# 从 APK 中找到的 key 和 IV
key = "This is the super secret key 123".encode("utf-8")
iv = bytes([0] * 16)

# 密文 Base64 解码
cipher_b64 = "i2soXgauVzM8iD/TBS8cbQ=="
cipher_bytes = base64.b64decode(cipher_b64)

# 解密
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(cipher_bytes)

# 去除填充
pad_len = plaintext[-1]
plaintext = plaintext[:-pad_len]

print("Decrypted password:", plaintext.decode("utf-8"))

