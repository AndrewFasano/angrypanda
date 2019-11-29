import angr
import claripy
import keystone
from ipdb import set_trace as d

pc = 0x4000
shellcode = b"mov eax, 0xffff; movzx  ebx,BYTE PTR [eax]; jmp +2; " + b"nop; "*10 # Jmp/nops to end

ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
claripy_solver = claripy.Solver()

insns, i_count = ks.asm(shellcode)
asm = b"".join([bytes([x]) for x in insns])
proj = angr.load_shellcode(asm, arch="i386", start_offset=pc, load_address=pc)
start_state = proj.factory.blank_state(addr=pc)

start_state.regs.eax = 0 # ? does this change anything/introduce the bug we have in the real one?

def jit_store(state):
    '''
    Immediately before dereferencing 0xFFFF, set a value there
    '''
    addr = state.inspect.mem_read_address
    addr_c = state.solver.eval(addr) # Could use claripy solver to check for multiple concrete values
    if state.inspect.mem_read_length==1:
        val = 0x41
    elif state.inspect.mem_read_length==4:
        val = 0x41414141
    else:
        raise RuntimeError("Unsupported length:", state.inspect.mem_read_length)

    print(f"JIT STORE to address 0x{addr_c:x} value=0x{val}")
    state.memory.store(addr_c, val) # Set the value

def do_jit(state):
    '''
    Concretize address - if it's not in our memory may, then we need to jit_store
    '''
    l = state.inspect.mem_read_length
    addr = state.inspect.mem_read_address
    addr_c = state.solver.eval(addr)

    angr_mem = state.memory.mem.load_objects(addr_c, l)
    return len(angr_mem)==0

def pre_ins(state):
    pc = state.ip.args[0]
    if pc == 0x4005:
        eax = state.regs.eax
        eax_c = state.solver.eval(eax)
        print(f"Instruciton at 0x{pc:x}. EAX={eax} == 0x{eax_c:x}")

start_state.inspect.b('instruction', action=pre_ins, when=angr.BP_BEFORE)
start_state.inspect.b('mem_read', condition=do_jit, action=jit_store, when=angr.BP_BEFORE)

simgr = proj.factory.simgr(start_state)

simgr.run(n=1)

final = simgr.active[0]
print(final)
print(final.regs.ebx)
d()
