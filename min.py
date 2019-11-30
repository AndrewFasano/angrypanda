import angr
import claripy
import keystone
import capstone
from ipdb import set_trace as d

pc = 0x4000
    #          00             ;  05
    #          08                       ; 0b           ; 0e;       ; 10 ; 11
shellcode  = b"mov eax, 0xcccc; movzx ebx, BYTE PTR [eax];"  + \
             b"movzx  ecx,BYTE PTR [ebx];" + \
             b"cmp ecx, 0x45; jne 0x4012; nop; jmp 0x4012;" + \
             b"nop; " * 20

# Shellcode will read memory at 0xCCCC, which we'll populate to be 0xFFFF JIT
# then it will read memory at 0xFFFF which we'll leave as unconstrained
# then there's a branch depending on the unconstrained value
# and a bunch of nops so angr doesn't ever think the next instructions are unconstrained

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
claripy_solver = claripy.Solver()

insns, i_count = ks.asm(shellcode, pc)
asm = b"".join([bytes([x]) for x in insns])
proj = angr.load_shellcode(asm, arch="i386", start_offset=pc, load_address=pc)
start_state = proj.factory.blank_state(addr=pc)

def jit_store(state):
    '''
    Immediately before dereferencing 0xFFFF, set a value there
    '''
    addr = state.inspect.mem_read_address
    addr_c = state.solver.eval(addr) # Could use claripy solver to check for multiple concrete values
    l = state.inspect.mem_read_length
    l = 4 # XXX: What? Why do we see length of 1 when it's 4 at 0x4005

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


    if addr_c == 0xFFFF:
        print("Leave unconstrainted") # XXX: Do nothing - Use angr's default fallback
    else:
        print(f"JIT STORE to address 0x{addr_c:x} value=0x{int_val:x} (len {l})")
        state.memory.store(addr_c, int_val, size=4) # Set the value

        # XXX: If we don't do this, the value isn't actually changed??? What??
        v = state.memory.load(addr_c)
        assert(state.solver.eval(v) == int_val)

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

simgr.explore(find=0x4010)

# After exploration we should have one item in `found` stash and one that's still active
assert(len(simgr.active)), "Nothing in active stash"
assert(len(simgr.found)),  "Nothing in found stash"

sym_addr = 0xFFFF

print(f"Evaluating mem:0x{sym_addr:x} in active state...")
active = simgr.active[0]
active_mem = active.memory.load(sym_addr, 1)
active_conc = active.solver.eval(active_mem)
print(f"0x{sym_addr:x} = 0x{active_conc:x} in active state...")

print(f"Evaluating mem:0x{sym_addr:x} in found state...")
found = simgr.found[0]
found_mem = found.memory.load(sym_addr, 1)
found_conc = found.solver.eval(found_mem)
print(f"0x{sym_addr:x} = 0x{found_conc:x} in found state...")

assert(active_conc != 0x45), "Active state incorrectly has soln value"
assert(found_conc == 0x45), "Found state doesn't have soln value"
