"""
    Code + Stack + Data


    Unicorn set up:
        
        - map virtual memory region (code + stack + data)
        - set esp to the high memory of the stack address mapping
        - set "bacon!" inside the data region at 0x300000

    Code: 
        - Typical function prologue
            * makes room on the stack for a local variable by subtracting 0x4
        - Put local variable 0x300000 onto the stack
        - Move 0x300000 into rax
        - Overwrite rax with the value found at 0x300000


    ```
        push   rbp                              function prologue
        mov    rbp,rsp                          function prologue
        sub    rsp,0x4                          room for local variable
        mov    DWORD PTR [rbp-0x4],0x300000     local variable on stack
        mov    rax,QWORD PTR [rbp-0x4]          move local into rax
        mov    rax,QWORD PTR [rax]              dereference rax into rax
    ```
"""


from unicorn import *
from unicorn.x86_const import *


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
    print(" - yes stack")
    print(" - yes data")
    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    # Maps out memory regions
    mu.mem_map(BASE_ADDR, BASE_SIZE)
    mu.mem_map(STACK_ADDR, STACK_SIZE)
    mu.mem_map(DATA_ADDR, DATA_SIZE)

    # Writes code and data to the mapped memory
    mu.mem_write(BASE_ADDR, CODE)
    mu.mem_write(DATA_ADDR, b"bacon!")

    # Sets the stack pointer
    mu.reg_write(UC_X86_REG_ESP, STACK_ADDR + STACK_SIZE)

    # Emulates
    mu.emu_start(BASE_ADDR, BASE_ADDR + len(CODE))

    # Grabs resulting registers
    rsp = mu.reg_read(UC_X86_REG_RSP)
    rbp = mu.reg_read(UC_X86_REG_RBP)
    rax = mu.reg_read(UC_X86_REG_RAX)

    # Reads 8 bytes of the data region
    data = mu.mem_read(DATA_ADDR, 0x8)

    # Local variable at [ebp - 0x4]
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
