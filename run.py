#!/usr/bin/env python3

# XXX: Once we identify the buffer address and mark as concrete via JIT,
# why doesn't it actually change the value in EAX? Things worked in min.py...?

# Run a program in eanda, transfer state into angr
# Similar to http://angr.io/blog/angr_symbion/
# and recreating something that was done in Avatar2

from sys import argv
from os import path
import capstone
import angr
import claripy
import logging

from panda import Panda, ffi, blocking
from panda.x86.helper import *
from ipdb import set_trace as d

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from io import BytesIO

logging.getLogger('angr').setLevel('WARNING') # Shut up, angr

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

mappings = {}
with open(path.join("toy", "foo"), 'rb') as f:
    our_elf = ELFFile(f)
    for section in our_elf.iter_sections():
        if not isinstance(section, SymbolTableSection): continue
        for symbol in section.iter_symbols():
            if len(symbol.name): # Sometimes empty
                mappings[symbol.name] = symbol['st_value']

START_ANGR = 0x804844d # nop
FIND_ADDR  = 0x8048482 # Moves 1 into eax before ret
AVOID      = 0x8048489 # Moves 0 into eax just before ret
START_MAIN = mappings['main']
END_MAIN   = 0x8048495 # Main's ret

def angr_insn_exec(state):
    """
    Debug callback - Print before each instruction we execute
    """
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

def angr_insn_after(state):
    """
    Debug callback - Print after
    """
    eax = state.solver.eval(state.regs.eax)
    edx = state.solver.eval(state.regs.edx)
    print(f"                eax {state.regs.eax} == 0x{eax:x}, edx = {state.regs.edx} == 0x{edx:x}\n")

    #if state.addr == 0x8048461 # Why didn't EAX change???

def jit_store(state):
    '''
    Immediately before dereferencing a pointer, set a value there
    '''
    addr = state.inspect.mem_read_address
    addr_c = state.solver.eval(addr) # XXX: what 
    l = state.inspect.mem_read_length
    # Could use claripy solver to check for multiple concrete values
    concrete_val = panda.virtual_memory_read(g_env, addr_c, l)
    int_val = int.from_bytes(concrete_val, byteorder='little')

    print(f"JIT STORE to address {addr}==0x{addr_c:x} pandavalue=0x{int_val:x}")
    state.memory.store(addr_c, int_val) # Set the value

def do_jit(state):
    '''
    Concretize address - if it's not in our memory may, then we need to jit_store
    '''
    l = state.inspect.mem_read_length
    addr = state.inspect.mem_read_address
    addr_c = state.solver.eval(addr)

    angr_mem = state.memory.mem.load_objects(addr_c, l)
    return len(angr_mem)==0
"""
def should_break(state):
    addr_bv = state.inspect.mem_read_address
    addr = state.solver.eval(addr_bv)

    print(f"\nDECISION: How to handle data at 0x{addr:x}")
    #print(f"\tBV Concrete: {addr_bv.concrete}")
    ptr_dest = state.memory.load(addr, state.inspect.mem_read_length, disable_actions=True, inspect=False)
    #if addr == 0xBfB6B51C:
    #    d()

    # The address being read isn't concrete. Yikes XXX how to handle
    if not addr_bv.concrete:
        #print("\tYIKES - Non-concrete address - copy from gueest??", addr_bv)
        return True

    # Some/All of the read is not concrete - XXX: Make sure to not recurse
    if not state.memory.load(addr, state.inspect.mem_read_length, disable_actions=True, inspect=False).concrete:
        #print(f"Reading missing data at 0x{addr:x} ({state.inspect.mem_read_length} bytes)")
        #print(f"\tReading non-concrete data - Copy from guest")
        return True

    # It's all concrete
    #print(f"\tReading angr's concrete data at 0x{addr:x}")
    return False

def mem_read_pre(state):
    print("MEM_READ_PRE")
    return

    print(state)
    d()
    addr_bv = state.inspect.mem_read_address # XXX: How to get addr?
    addr = state.solver.eval(addr_bv)
    byte_length = state.inspect.mem_read_length

    concrete_val = panda.virtual_memory_read(env, addr, byte_length) # Safe - reading panda memory, no recusion
    int_val = int.from_bytes(concrete_val, byteorder='little')

    #state.solver.add(state.inspect.mem_read_expr == int_val)

def should_break_pre(state):
    '''
    Given an address we're about to read, determine if it's symbolic. If it is, and it's NOT the one we want to be symbl
    then call mem_read_pre to copy real PANDA data into our state
    '''

    addr = state.solver.eval(state.inspect.mem_read_address)

    if addr == 0xBFB6B514:
        print("XXX: HARDCODED ADDR TO LEAVE SYMBOLIC")
        return False
    '''
    expr = state.inspect.mem_read_expr

    if not expr:
        print(f"XXX: Unknown expr, addr = 0x{addr:x}")
    else:
        # First chewck if expr is uninit
        if expr.uninitialized:
            print("Expression unitialized - Load from PANDA memory")
            return True
    '''

    angr_mem = state.memory.mem.load_objects(addr, state.inspect.mem_read_length) # Maybe len*4?
    #print("ANGR_MEM:", angr_mem)
    if not len(angr_mem):
        print(f"Angr mem empty at 0x{addr:x}")
        return True

    assert(len(angr_mem) == 1), "Not sure what's going on, multiple angr mem states"

    '''
    if isinstance(angr_mem[0][1].object.args[0], int):
        return False

    if isinstance(angr_mem[0][1].object.args[0], claripy.ast.bv.BV):
        print("XXX what")
        return True # XXX Not sure what's going on?

    if angr_mem[0][1].object.args[0].unitialized:
        print(f"0x{addr:x} points ot unitialized memory. Construct something from PANDA memory!")
        return True
    '''


'''
if isinstance(angr_mem[0][1].object, claripy.ast.bv.BV):
    # It's a bitvector
    if isinstance(angr_mem[0][1].object.args[0], claripy.ast.bv.BV): # Arg is also a BV
        print("ARG BV")
        return False

    if angr_mem[0][1].object.uninitialized:
       print("Uninitialized bitvector")
       return True # XX???
'''

return False

def mem_read(state):
    '''
    On uninitialized memory reads, pull in concrete values from panda
    '''
    global mapped
    addr_bv = state.inspect.mem_read_address
    addr = state.solver.eval(addr_bv)
    byte_length = state.inspect.mem_read_length
    print(f"\tmem_read handler addr=0x{addr:x}, addr_bv = {addr_bv}")

    concrete_val = panda.virtual_memory_read(env, addr, byte_length) # Safe - reading panda memory, no recusion
    int_val = int.from_bytes(concrete_val, byteorder='little')

    #if addr == 0xBFB6B51C:
    #    print(f"Leave symbolic data at 0x{addr:x} isntead of PANDA's 0x{int_val:x}")
    #    return

    if int_val == 0x41:
        print("XXX: SKIP 41, leave symbolic")
        return

    print(f"\tSYNC MEMORY: set 0x{addr:x} = 0x{int_val:x}, len={byte_length}")
    #state.memory.store(addr=addr, data=int_val)
    state.solver.add(state.inspect.mem_read_expr == int_val)


"""

mem_reads = set()

def should_copy(state):
    """
    Return true if the current instruction is going to try reading uninit memory
    and we need to copy it (For now we ignore the case when we want to leave it as symbolic)
    """
    global mem_reads

    read_addr = state.inspect.mem_read_address
    if isinstance(read_addr, claripy.ast.bv.BV) and \
       len(read_addr.args) and \
       isinstance(read_addr.args[0], claripy.ast.bv.BV): # Symbolic addr being read
        if read_addr.args[0].uninitialized:
            print("WARNING: Symbolic address read from!")
            return True # True means we concretize the address. Otherwise we leave symbolic?

    addr = state.solver.eval(read_addr)
    angr_mem = state.memory.mem.load_objects(addr, state.inspect.mem_read_length)
    #print(f"\tRead from memory {state.inspect.mem_read_address} => 0x{addr:x}")
    mem_reads.add(addr)

    if addr == 0: # Debug, it should be init
        d()

    #if addr == 0xBFB6B514: # This is the address of the POINTER to our buffer
    #    print("XXX: HARDCODED ADDR TO LEAVE SYMBOLIC")
    #    return False

    if not len(angr_mem): # Memory missing from angr, need to populate it
        print(f"\tReading without angr memory from 0x{addr:x}, {state.inspect.mem_read_length} bytes")
        return True

g_env = None
def mem_read_pre(state):
    '''
    Copy concrete state into angr memory. For now, just set everything to a constant
    '''
    global g_env

    #if state.inspect.mem_read_address.op.args[0].uninitialized:
    #    print("YIKES")

    addr = state.solver.eval(state.inspect.mem_read_address)
    byte_length = state.inspect.mem_read_length
    concrete_val = panda.virtual_memory_read(g_env, addr, byte_length)
    int_val = int.from_bytes(concrete_val, byteorder='little')

    print(f"\tAdd concrete data to angr's memory:0x{addr:x} = 0x{int_val:x} ({byte_length} bytes)")
    state.memory.store(addr, int_val)
    d()


@blocking
def run_foo():
    panda.record_cmd("toy/foo; echo $?", copy_directory="toy", recording_name="foo.recording")
    panda.stop_run()

if not path.isfile("foo.recording-rr-nondet.log"):
    print("Generating new recording...")
    panda.queue_async(run_foo)
    panda.run()
    print("Done!")


@panda.cb_insn_translate(procname="foo") # Only trigger insn_exec when we're in foo's main
def ret_true(env, tb):
    pc = panda.current_pc(env)
    return pc >= START_MAIN  and pc <= END_MAIN


def do_angr(panda, env, pc):
    """
    Given a panda state, do some symbolic execution with angr
    """

    global g_env
    g_env = env

    # Initialze angr - Place this function into memory as shellcode
    mem = panda.virtual_memory_read(env, pc, END_MAIN-pc)
    project = angr.load_shellcode(mem, arch='i386', load_address=pc) # TODO: Auto ID arch?

    """
    # Want to load project with a more flexible backend - should pull in executable memory on demand
    project = angr.Project(
                            BytesIO(b"a"),
                            main_opts={
                                'backend': 'blob',
                                'arch': 'i386'
                                'entry_point': 0
                                'base_addr': 0
                                }
                            )

    # Now copy in pages of memory on demmand, into project.Loader

    # For now just map in the rest of main
    obj = cle.backends.Blob(mem)
    project.loader.add_object(obj, pc)

    d()
    """

    # Explore
    start_state = project.factory.blank_state(addr=pc)

    # Copy concrete registers into angr from panda
    for (angr_reg, panda_reg) in zip([x.lower() for x in registers.keys()], registers.values()):
        val = env.env_ptr.regs[panda_reg]
        print(f"Set {angr_reg} = 0x{val:x}")
        setattr(start_state.regs, angr_reg, val)

    # Debugging, print at start and end of simulating each instruction
    start_state.inspect.b('instruction', action=angr_insn_exec, when=angr.BP_BEFORE)
    start_state.inspect.b('instruction', action=angr_insn_after, when=angr.BP_AFTER)

    # Whenever we read a symbolic value, use mem_read to find a concrete value
    #start_state.inspect.b('mem_read', action=mem_read_pre, condition=should_copy,
    #                        when=angr.BP_BEFORE) # New version, was should_break
    start_state.inspect.b('mem_read', condition=do_jit, action=jit_store,
                            when=angr.BP_BEFORE)

    #start_state.memory.store(0xbf982714, 0x41414141) # XXX TEST - POINTER ADDRESS
    #start_state.memory.store(0x97c6008, 0x12345678) # XXX TEST - POINTER VAL

    simgr = project.factory.simulation_manager(start_state)

    # Just step a single BB
    for i in range(5):
        print(f"\nStep simulation {i}th time")
        simgr.step()
    d()
    return

    # Explore to find a way to get to FIND_ADDR while avoiding AVOID
    simgr.explore(find=FIND_ADDR, avoid=[AVOID])

    """
    print("mem_reads:")
    for addr in sorted(mem_reads):
        print(hex(addr))
    """

    if not len(simgr.found):
        print("All failure :(")
        d()
        return

    final_state = simgr.found[0]
    for const in final_state.solver.constraints:
        for x in final_state.solver.describe_variables(const):
            print(x[0], hex(x[1]), const.op, hex(final_state.solver.eval(const.args[1])))
    d()

@panda.cb_insn_exec
def insn_exec(env, pc): # Only called for main
    #print("INSTRUMENTED:", hex(pc))
    if pc == 0x8048468:
        eax = env.env_ptr.regs[R_EAX]
        print("BUFFER IS AT", hex(eax))

    if pc == START_ANGR:
        print(f"START ANGR from 0x{pc:x}")
        do_angr(panda, env, pc)

    return 0

panda.run_replay("foo.recording")
