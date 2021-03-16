"""
    Only code
        - no stack
        - no data

    rax starts with 5


    ```
        add rax, 4      =>  rax: 9
        sub rax, 2      =>  rax: 7
        add rax, 5      =>  rax: 12
        sub rax, 2      =>  rax: 10
    ```
"""

from unicorn import *
from unicorn.x86_const import *

CODE = b"\x48\x83\xC0\x04\x48\x83\xE8\x02\x48\x83\xC0\x05\x48\x83\xE8\x02"
BASE = 0x004000000

try:
    print("-" * 32)
    print("Emulating x86_64")
    print(" - no stack")
    print(" - no data")
    
    # Unicorn engine
    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    # Map out the base / .text section
    mu.mem_map(BASE, 1024*1024)

    # Write the code to the base address
    mu.mem_write(BASE, CODE)

    # Set rax to 5
    mu.reg_write(UC_X86_REG_RAX, 0x5)

    # Emulate the binary
    mu.emu_start(BASE, BASE+len(CODE))

    # Read registers
    r_rax = mu.reg_read(UC_X86_REG_RAX)

    print("-" * 32)
    print("Result")
    print(f" - rax: {r_rax}")
except Exception as e:
    print(f"err: {e}")
