# test_crypto_import.py
try:
    from Crypto.Cipher import AES
    print("✅ pycryptodome 正常工作")
except Exception as e:
    print("❌ 导入失败:", e)

