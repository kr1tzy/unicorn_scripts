"""
    Code + Stack + Data

    (Typical function prologue)
    (making room on the stack for local by subtracting 0x4)
    (moving 0x300000 onto the stack)
    (getting the value at address 0x300000 in rax)
    (put the value sitting at the data address 0x300000 into rax)

    push   rbp
    mov    rbp,rsp
    sub    rsp,0x4
    mov    DWORD PTR [rbp-0x4],0x300000
    mov    rax,QWORD PTR [rbp-0x4]
    mov    rax,QWORD PTR [rax]
"""


from unicorn import *
from unicorn.x86_const import *
import struct


CODE = b"\x55\x48\x89\xE5\x48\x83\xEC\x04\xC7\x45\xFC\x00\x00\x30\x00\x48\x8B\x45\xFC\x48\x8B\x00"
BASE_ADDR  = 0x00400000
DATA_ADDR  = 0x00300000
STACK_ADDR = 0x00200000
BASE_SIZE  = 1024*1024
STACK_SIZE = 1024*1024
DATA_SIZE  = 1024*1024


try:
    print("-" * 32)
    print("Emulating x86_64")
    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    # Maps out memory regions
    mu.mem_map(BASE_ADDR, BASE_SIZE)
    mu.mem_map(STACK_ADDR, STACK_SIZE)
    mu.mem_map(DATA_ADDR, DATA_SIZE)

    # Writes code and data to the mapped memory
    mu.mem_write(BASE_ADDR, CODE)
    mu.mem_write(DATA_ADDR, b"bacon!")

    # Sets the stack pointer
    mu.reg_write(UC_X86_REG_ESP, STACK_ADDR + STACK_SIZE - 0x20)

    # Emulates
    mu.emu_start(BASE_ADDR, BASE_ADDR + len(CODE))

    # Grabs resulting registers and data
    rsp = mu.reg_read(UC_X86_REG_RSP)
    rbp = mu.reg_read(UC_X86_REG_RBP)
    rax = mu.reg_read(UC_X86_REG_RAX)
    data = mu.mem_read(DATA_ADDR, 0x20)

    # Local variable from [ebp - 0x4]
    rbp_4 = mu.mem_read(rbp - 4, 0x4)

    print("-" * 32)
    print("Result")
    print(f" - rsp: {hex(rsp)}")
    print(f" - rbp: {hex(rbp)}")
    print(f" - rax: {hex(rax)} (aka '{rax.to_bytes(8, 'little').decode()}')")
    print(f" - data: {data}")
    print(f" - [rbp - 0x4]: {hex(int.from_bytes(rbp_4, 'little'))}")

except Exception as e:
    print(f"err: {e}")
