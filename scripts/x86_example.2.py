"""
    Code + Stack

    rax starts with 0x1 (set on line 41)
    rbx starts with 0x2 (set on line 42)
    rcx starts with 0x3 (set on line 43)


    ```
        push rcx        [push rcx onto the stack]
        pop rax         rax: 0x3
        add rax, rbx    rax: 0x5
    ```
"""

from unicorn import *
from unicorn.x86_const import *

CODE = b"\x51\x58\x48\x01\xD8"
BASE = 0x004000000
STACK_ADDR = 0x00200000
STACK_SIZE = 1024*1024


try:
    print("-" * 32)
    print("Emulating x86_64")
    print(" - yes stack")
    print(" - no data")
    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    # Map out memory
    mu.mem_map(BASE, 1024*1024)
    mu.mem_map(STACK_ADDR, STACK_SIZE)

    # Write the code to the base
    mu.mem_write(BASE, CODE)
    
    # Set the starting value of the stack pointer
    mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE)

    # Set the registers
    mu.reg_write(UC_X86_REG_RAX, 0x1)
    mu.reg_write(UC_X86_REG_RBX, 0x2)
    mu.reg_write(UC_X86_REG_RCX, 0x3)

    # Emulate
    mu.emu_start(BASE, BASE + len(CODE))

    # Read values
    r_rax = mu.reg_read(UC_X86_REG_RAX)
    r_rbx = mu.reg_read(UC_X86_REG_RBX)
    r_rcx = mu.reg_read(UC_X86_REG_RCX)

    print("-" * 32)
    print("Result")
    print(f" - rax: {r_rax}")
    print(f" - rbx: {r_rbx}")
    print(f" - rcx: {r_rcx}")

except Exception as e:
    print(f"err: {e}")
