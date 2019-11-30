import angr
import claripy
import keystone
import capstone
from ipdb import set_trace as d

START_PC = 0x4000
EXPLORE_GOAL  = START_PC + 0xE # Address to find with angr
EXPLORE_AVOID = START_PC + 0x10 # Address to avoid
sym_addr = 0xFFFF # Address to leave as symbolic
shellcode  = [b"mov eax, 0xcccc",          # +0x00
              b"mov ebx, DWORD PTR [eax]", # +0x05
              b"mov ecx, DWORD PTR [ebx]", # +0x07
              b"cmp ecx, 0x45",            # +0x09
              b"jne 0x4010",               # +0x0C
              b"jmp 0x4011",               # +0x0E Only hit when mem:0xFFFF==0x45
              b"nop",                      # +0x10 Only hit when mem0xFFFF!=0x45
              b"nop",                      # +0x11 hit always
              b"nop",                      # Junk so angr doesn't
              b"nop",                      # think there are symbolic insns
              ]

# Shellcode will read memory at 0xCCCC, which we'll populate to be 0xFFFF through a breakpoint (JIT)
# then it will read memory at 0xFFFF which we'll leave as unconstrained data.
# Then there's a branch depending on the unconstrained value
# and an infinite loop at the end. Padded with nops so angr never reads ahead and sees symbolic code

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
claripy_solver = claripy.Solver()

insns, i_count = ks.asm(b";".join(shellcode), START_PC)
if i_count != len(shellcode): # Ensure our assembly compiles cleanly!
    print("Failed to assemble shellcode")
    for insn in shellcode:
        success = False
        try:
            asm, success = ks.asm(insn) # PC doesn't matter
        except:
            pass
        if not success:
            print("Error compiling: {}".format(insn))
    raise RuntimeError("Failed to compile input")

asm = b"".join([bytes([x]) for x in insns])
proj = angr.load_shellcode(asm, arch="i386", start_offset=START_PC, load_address=START_PC)
start_state = proj.factory.blank_state(addr=START_PC)
start_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY) # Silence unconstrained mem read warnings

def jit_store(state):
    '''
    Immediately before dereferencing sym_addr, set a value there
    '''
    addr = state.inspect.mem_read_address
    addr_c = state.solver.eval(addr) # Could use claripy solver to check for multiple concrete values
    l = state.inspect.mem_read_length

    # Could use claripy solver to check for multiple concrete values
    concrete_byte_val = bytes([0, 0, 0xff, 0xff]) #panda.virtual_memory_read(g_env, addr_c, l)
    byte_int_val = int.from_bytes(concrete_byte_val, byteorder='big') # XXX: keep as big endian here! We'll swap
                                                                      #      to little endian (if needed) later.
    if l == 1:
        mask = 0xFF
    elif l == 4:
        mask = 0xFFFFFFFF
    else:
        raise RuntimeError("No mask for length {l}")
    int_val = byte_int_val&mask


    if addr_c == sym_addr:
        print(f"JIT IGNORE: leave {l} bytes unconstrained at mem:0x{int_val:x}") # XXX: Do nothing - Use angr's default fallback
    else:
        print(f"JIT STORE: save value=0x{int_val:x} (len {l}) to address mem:0x{addr_c:x}")
        state.memory.store(addr_c, int_val, size=4, endness="Iend_LE") # Set the value

def do_jit(state):
    '''
    Concretize address - if it's not in our memory may, then we need to jit_store
    '''
    l = state.inspect.mem_read_length
    addr = state.inspect.mem_read_address
    addr_c = state.solver.eval(addr)

    if addr_c > 0x4000 and addr_c < 0x5000: # No copying insns
        return False

    angr_mem = state.memory.mem.load_objects(addr_c, l)
    return len(angr_mem)==0

def angr_insn_exec(state):
    """
    Debug callback - Print before each instruction we execute
    """
    if state.inspect.instruction in [0x4008]: # After we deref EBX
        eax = state.solver.eval(state.regs.eax)
        ebx = state.solver.eval(state.regs.ebx)
        print(f"\nEAX={state.regs.eax}, 0x{eax:x}, EBX={state.regs.ebx}, 0x{ebx:x}\n--------")

    ops = []
    for i in range(8):
        op = state.mem[state.inspect.instruction+i]
        if op.byte.resolved.uninitialized:
            break
        ops.append(op.byte.resolved.args[0])

    op_bytes = b"".join([bytes([x]) for x in ops])
    for i in md.disasm(op_bytes, state.inspect.instruction):   
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        break

start_state.inspect.b('instruction', action=angr_insn_exec, when=angr.BP_BEFORE)
start_state.inspect.b('mem_read', condition=do_jit, action=jit_store, when=angr.BP_BEFORE)

simgr = proj.factory.simgr(start_state)

simgr.explore(find=EXPLORE_GOAL,avoid=[EXPLORE_AVOID])

# After exploration we should have one item in `found` stash and one that's still active
assert(len(simgr.found)),  "Nothing in found stash"
assert(len(simgr.avoid)), "Nothing in avoid stash"

print(f"\nEvaluating mem:0x{sym_addr:x} in avoid state...")
avoid = simgr.avoid[0]
avoid_mem = avoid.memory.load(sym_addr, 1)
avoid_conc = avoid.solver.eval(avoid_mem)
print(f"mem:0x{sym_addr:x} = 0x{avoid_conc:x} in avoid state...")

print(f"\nEvaluating mem:0x{sym_addr:x} in found state...")
found = simgr.found[0]
found_mem = found.memory.load(sym_addr, 1)
found_conc = found.solver.eval(found_mem)
print(f"mem:0x{sym_addr:x} = 0x{found_conc:x} in found state...")

assert(avoid_conc != 0x45), "Avoid state incorrectly has soln value"
assert(found_conc == 0x45), "Found state doesn't have soln value"
print(f"Success, found state has solution value of 0x{found_conc:x}")
