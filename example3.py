from unicorn import *
from unicorn.x86_const import *
import struct

"""
    Code + Stack + Data

    (Typical function prologue)
    (making room on the stack by subtracting 0x10)
    (moving 0x300000 onto the stack)
    (getting the value at address 0x300000)

    push ebp
    mov ebp, esp
    sub esp, 0x10
    mov DWORD PTR [ebp-0x4], 0x300000
    mov eax, DWORD PTR [ebp-0x4]
"""
CODE = "\x55\x89\xE5\x83\xEC\x10\xC7\x45\xFC\x00\x00\x30\x00\x8B\x45\xFC"


BASE_ADDR  = 0x00400000
DATA_ADDR  = 0x00300000
STACK_ADDR = 0x00200000
BASE_SIZE  = 1024*1024
STACK_SIZE = 1024*1024
DATA_SIZE  = 1024*1024


# Takes a 4-byte string and converts it to an integer which represents this data in little endian.
def u32(data):
    return struct.unpack("I", data)[0]


def main():
    try:
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        # Maps out memory regions
        mu.mem_map(BASE_ADDR, BASE_SIZE)
        mu.mem_map(STACK_ADDR, STACK_SIZE)
        mu.mem_map(DATA_ADDR, DATA_SIZE)

        # Writes code and data to the mapped memory
        mu.mem_write(BASE_ADDR, CODE)
        mu.mem_write(DATA_ADDR, "bacon!")

        # Sets the stack pointer
        mu.reg_write(UC_X86_REG_ESP, STACK_ADDR + STACK_SIZE - 0x20)

        # Emulates
        mu.emu_start(BASE_ADDR, BASE_ADDR + len(CODE))


        # Grabs resulting registers and data
        esp = mu.reg_read(UC_X86_REG_ESP)
        ebp = mu.reg_read(UC_X86_REG_EBP)
        eax = mu.reg_read(UC_X86_REG_EAX)
        data = mu.mem_read(DATA_ADDR, 0x20)


        # Local variable from [ebp - 0x4]
        ebp_4 = mu.mem_read(ebp - 4, 0x4)

        print("Result")
        print(" - esp: " + str(hex(esp)).rstrip("L"))
        print(" - ebp: " + str(hex(ebp)).rstrip("L"))
        print(" - eax: " + str(hex(eax)).rstrip("L"))
        print(" - data: " + data)
        print(" - [ebp-0x4]: " + str(hex(u32(ebp_4))))
    except Exception as e:
        print("Err: %s" % e)




if __name__ == "__main__":
    main()
