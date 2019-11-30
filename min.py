import angr
import claripy
import keystone
import capstone
from ipdb import set_trace as d

START_PC = 0x4000
EXPLORE_GOAL=START_PC+0xE # Address to find with angr
sym_addr = 0xFFFF # Address to leave as symbolic
shellcode  = [b"mov eax, 0xcccc",          # +0x00
              b"mov ebx, DWORD PTR [eax]", # +0x05
              b"mov ecx, DWORD PTR [ebx]", # +0x07
              b"cmp ecx, 0x45",            # +0x09
              b"jne 0x400F",               # +0x0C
              b"nop",                      # +0x0E
              b"jmp 0x400F",               # +0x0F # Loop forever.
              b"nop",                      # When angr looks ahead,
              b"nop",                      # make sure we always
              b"nop",                      # have concrete instructions
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
    concrete_byte_val = bytes([0xff, 0xff, 0, 0]) #panda.virtual_memory_read(g_env, addr_c, l)
    byte_int_val = int.from_bytes(concrete_byte_val, byteorder='little')
    if l == 1:
        mask = 0xFF
    elif l == 4:
        mask = 0xFFFFFFFF
    else:
        raise RuntimeError("No mask for length {l}")
    int_val = byte_int_val&mask


    if addr_c == sym_addr:
        print(f"JIT IGNORE: leave {l} bytes unconstrained at mem:0x{int_val}") # XXX: Do nothing - Use angr's default fallback
    else:
        print(f"JIT STORE: save value=0x{int_val:x} (len {l}) to address mem:0x{addr_c:x}")
        state.memory.store(addr_c, int_val, size=4) # Set the value

        # XXX: If we don't do this, the value isn't actually changed??? What??
        v = state.memory.load(addr_c)
        #assert(state.solver.eval(v) == int_val)

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
        print("0x%x:\t%s\t%s\t(%d bytes)" %(i.address, i.mnemonic, i.op_str, len(i.bytes)))
        break

start_state.inspect.b('instruction', action=angr_insn_exec, when=angr.BP_BEFORE)
start_state.inspect.b('mem_read', condition=do_jit, action=jit_store, when=angr.BP_BEFORE)

simgr = proj.factory.simgr(start_state)

simgr.explore(find=EXPLORE_GOAL)

# After exploration we should have one item in `found` stash and one that's still active
assert(len(simgr.active)), "Nothing in active stash"
assert(len(simgr.found)),  "Nothing in found stash"

print(f"\nEvaluating mem:0x{sym_addr:x} in active state...")
active = simgr.active[0]
active_mem = active.memory.load(sym_addr, 1)
active_conc = active.solver.eval(active_mem)
print(f"mem:0x{sym_addr:x} = 0x{active_conc:x} in active state...")

print(f"\nEvaluating mem:0x{sym_addr:x} in found state...")
found = simgr.found[0]
found_mem = found.memory.load(sym_addr, 1)
found_conc = found.solver.eval(found_mem)
print(f"mem:0x{sym_addr:x} = 0x{found_conc:x} in found state...")

assert(active_conc != 0x45), "Active state incorrectly has soln value"
assert(found_conc == 0x45), "Found state doesn't have soln value"
print(f"Success, found state has solution value of 0x{found_conc:x}")
