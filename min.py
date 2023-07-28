import angr
import claripy
import keystone
import capstone
import io
import os

from pandare import Panda
from angrypanda import AngryPanda

START_PC = 0x1000
EXPLORE_GOAL  = START_PC + 0xE # Address to find with angr
EXPLORE_AVOID = START_PC + 0x10 # Address to avoid

COND_TRUE = False # Should concrete execution hit the true or false branch?

sym_addr = 0x4010 # Address to leave as symbolic
shellcode  = [b"mov eax, 0x4000",          # +0x00
              b"mov ebx, DWORD PTR [eax]", # +0x05
              b"mov ecx, DWORD PTR [ebx]", # +0x07
              b"cmp ecx, 0x45",            # +0x09
              b"jne 0x1010",               # +0x0C
              b"jmp 0x1012",               # +0x0E Only hit when mem:0xFFFF==0x45
              b"xor edx, edx",             # +0x10 Only hit when mem0xFFFF!=0x45
              b"nop",                      # +0x12 hit always
              b"cmp edx, 0",               # +0x14
              b"jnz 0x1020",               # +0x17
              b"nop",                      # +0x18 Junk so angr doesn't
              b"nop",                      # +0x19 think there are symbolic insns
              b"nop",                      # +0x1a
              b"hlt",                      # +0x1b
              ]

# Shellcode will read memory at 0xCCCC, which we'll populate to be 0xFFFF through a breakpoint (JIT)
# then it will read memory at 0xFFFF which we'll leave as unconstrained data.
# Then there's a branch depending on the unconstrained value
# and an infinite loop at the end. Padded with nops so angr never reads ahead and sees symbolic code


md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)

insns, i_count = ks.asm(b";".join(shellcode), START_PC)
if i_count != len(shellcode):
    raise RuntimeError("Failed to compile input")

stop_addr = START_PC + 0x1b

print("INSNS:", insns)
print("STOP:", hex(stop_addr))

# Convert insns from list of ints to bytes
insns = [bytes([x]) for x in insns]

# Create a machine of type 'configurable' but with just a CPU specified (no peripherals or memory maps)
panda = Panda("i386", extra_args=["-M", "configurable", "-nographic"])

@panda.cb_after_machine_init
def setup(cpu):
    '''
    After our CPU has been created, allocate memory and set starting state
    '''
    # map 2MB memory for this emulation
    panda.map_memory("mymem", 0x1000, START_PC)

    # Write code into memory
    panda.physical_memory_write(START_PC, insns)

    panda.map_memory("mem2", 0x1000, 0x4000)
    panda.physical_memory_write(0x4000, bytes([0x10, 0x40, 0, 0])) # Mem[0x4000] = 0x4010

    if COND_TRUE: 
        # Mem[0x4010] = 0x45
        panda.physical_memory_write(sym_addr, bytes([0x45, 0, 0, 0])) # TRUE
    else:
        # Mem[0x4010] != 0x45
        panda.physical_memory_write(sym_addr, bytes([0x40, 0, 0, 0])) # False

    # Set up registers with concrete state
    panda.arch.set_reg(cpu, "EAX", 0x1)
    panda.arch.set_reg(cpu, "EBX", 0x2)
    panda.arch.set_reg(cpu, "ECX", 0x3)
    panda.arch.set_reg(cpu, "EDX", 0x12345678) # If above is true, this will end as 0

    # Set starting_pc
    panda.arch.set_pc(cpu, START_PC)
    print(f"PC is 0x{panda.arch.get_pc(cpu):x}")

panda.cb_insn_translate(lambda x,y: True)

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
@panda.cb_insn_exec
def on_insn(cpu, pc):
    '''
    At each instruction, print capstone disassembly.
    When we reach stop_addr, dump registers and shutdown
    '''
    if pc == stop_addr:
        print("Finished execution. CPU registers are:")
        panda.arch.dump_regs(cpu)

        # TODO: we need a better way to stop execution in the middle of a basic block
        os._exit(0)

    code = panda.virtual_memory_read(cpu, pc, 12)
    for i in md.disasm(code, pc):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        break

    if pc == START_PC + 5:
        print("DO SYMEX")
        panda.pyplugins.ppp.AngryPanda.run_symex(cpu, pc, EXPLORE_GOAL, EXPLORE_AVOID, [sym_addr])

    return 0

# Start PANDA running. Callback functions will be called as necessary
panda.pyplugins.load(AngryPanda)
panda.run()