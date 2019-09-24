from unicorn import *
from unicorn.x86_const import *
"""
    Only code

    (rax starts at 5)

    add rax, 4  - rax: 9
    sub rax, 2  - rax: 7
    add rax, 5  - rax: 12
    sub rax, 2  - rax: 10
"""

CODE = "\x48\x83\xC0\x04\x48\x83\xE8\x02\x48\x83\xC0\x05\x48\x83\xE8\x02"
BASE = 0x004000000

try:
    print("Emulating x86_64")
    
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

    print("Done")

    r_rax = mu.reg_read(UC_X86_REG_RAX)
    print("Rax: " + str(r_rax))
except Exception as e:
    print("Err: %s" % e)
