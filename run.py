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

buffer_addr = None # Dynamically identified - Address of buffer returned from malloc

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
    #eax = state.solver.eval(state.regs.eax)
    #edx = state.solver.eval(state.regs.edx)
    #print(f"                eax  0x{eax:x}, edx 0x{edx:x}\n")

    print("-------")

def jit_store(state):
    '''
    Immediately before dereferencing a pointer, set a value there
    '''
    addr = state.inspect.mem_read_address
    addr_c = state.solver.eval(addr) # XXX: what 

    # We get little endian value from angr (if it's a LE arch). 
    # Flip to normal so we can compare against buffer address and print sane outputs
    #addr_c_noend = int.from_bytes((addr_c).to_bytes(4, byteorder='big'), byteorder='little')
    addr_c_noend = addr_c

    l = state.inspect.mem_read_length
    # Could use claripy solver to check for multiple concrete values
    concrete_byte_val = panda.virtual_memory_read(g_env, addr_c_noend, l)
    byte_int_val = int.from_bytes(concrete_byte_val, byteorder='big') # XXX: keep as big endian here! We'll swap
                                                                      #      to little endian (if needed) later.
    if l == 1:
        mask = 0xFF
    elif l == 4:
        mask = 0xFFFFFFFF
    else:
        raise RuntimeError("No mask for length {l}")

    int_val = byte_int_val&mask

    # Mask int_val to only be of length l bytes

    global buffer_addr
    assert(buffer_addr is not None), "Unset addr buffer"
    if addr_c_noend in range(buffer_addr, buffer_addr+4):
        print(f"MAKE SYMBOLIC AT 0x{addr_c_noend:x} instead of 0x{int_val:x} (len: {l})")
        # None of the following things work, instead we just use angr's built-in handling
        # of unknown values which prints a warning (useful for debugging) the first time we hit this case
        #name = f"panda_uncons_0x{addr_c:x}"
        #unc = state.memory.get_unconstrained_bytes(name, l, inspect=False)
        #state.memory.store(addr_c, unc) # Set to be unconstrained

        # Hardcode a junk value to the address, then replace it with symbolic data
        #state.memory.store(addr_c, 0, inspect=False) # XXX: This doesn't take into account length?
        #state.memory.make_symbolic(name, addr_c, l)

        #state.solver.Unconstrained(name, bits=l*8, key=('panda_uncon', addr_c), inspect=False, events=False)

    else:
        print(f"JIT STORE to address {addr}==0x{addr_c_noend:x} pandavalue=0x{int_val:x} len: {l}")
        state.memory.store(addr_c, int_val, endness="Iend_LE") # Set the value

def do_jit(state):
    '''
    Concretize address - if it's not in our memory may, then we need to jit_store
    '''
    l = state.inspect.mem_read_length
    addr = state.inspect.mem_read_address
    addr_c = state.solver.eval(addr)

    angr_mem = state.memory.mem.load_objects(addr_c, l)

    return len(angr_mem)==0

def should_copy(state):
    """
    Return true if the current instruction is going to try reading uninit memory
    and we need to copy it (For now we ignore the case when we want to leave it as symbolic)
    """

    read_addr = state.inspect.mem_read_address
    if isinstance(read_addr, claripy.ast.bv.BV) and \
       len(read_addr.args) and \
       isinstance(read_addr.args[0], claripy.ast.bv.BV): # Symbolic addr being read
        if read_addr.args[0].uninitialized:
            print("WARNING: Symbolic address read from!")
            return True # True means we concretize the address. Otherwise we leave symbolic?

    addr = state.solver.eval(read_addr)
    angr_mem = state.memory.mem.load_objects(addr, state.inspect.mem_read_length)

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

@panda.cb_insn_translate(procname="foo") # Only trigger insn_exec when we're in foo's main
def in_foo(env, tb):
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
    """

    # Explore
    start_state = project.factory.blank_state(addr=pc)
    #start_state.options.add(ANGR.SYMBOL_FILL_UNCONSTRAINED_MEMORY)

    # Copy concrete registers into angr from panda
    for (angr_reg, panda_reg) in zip([x.lower() for x in registers.keys()], registers.values()):
        val = env.env_ptr.regs[panda_reg]
        #print(f"Set {angr_reg} = 0x{val:x}")
        setattr(start_state.regs, angr_reg, val)

    # Debugging, print at start and end of simulating each instruction
    start_state.inspect.b('instruction', action=angr_insn_exec, when=angr.BP_BEFORE)
    start_state.inspect.b('instruction', action=angr_insn_after, when=angr.BP_AFTER)

    # Whenever we read a symbolic value, use mem_read to find a concrete value
    #start_state.inspect.b('mem_read', action=mem_read_pre, condition=should_copy,
    #                        when=angr.BP_BEFORE) # New version, was should_break
    start_state.inspect.b('mem_read', condition=do_jit, action=jit_store,
                            when=angr.BP_BEFORE)

    simgr = project.factory.simulation_manager(start_state)

    # Explore to find a way to get to FIND_ADDR while avoiding AVOID
    simgr.explore(find=FIND_ADDR, avoid=[AVOID])

    assert(len(simgr.found)), d()

    final_state = simgr.found[0]
    """
    # Bad representation of buffer, combines each byte into the constraints on the whole 4-byte object
    for const in final_state.solver.constraints:
        print(const.args[1])
        for x in final_state.solver.describe_variables(const):
            print(x[0], hex(x[1]), const.op, hex(final_state.solver.eval(const.args[1])))
    """
    buf = final_state.memory.load(buffer_addr, 4)
    soln = final_state.solver.eval(buf)
    soln_s = ''.join(chr((soln>>8*(4-byte-1))&0xFF) for byte in range(4))

    print("Solution:", hex(soln), soln_s)
    soln_sum = sum([ord(x) for x in soln_s])
    assert(soln_sum == 0x108), "Invalid solution"

    return soln_s

@panda.cb_insn_exec
def insn_exec(env, pc): # Only called for main
    global buffer_addr
    if pc == 0x8048426:
        eax = env.env_ptr.regs[R_EAX]
        #buffer_addr = eax
        #print(f"Buffer NORM is at 0x{buffer_addr:x}")
        # flip from LE to normal
        buffer_addr = int.from_bytes((eax).to_bytes(4, byteorder='big'), byteorder='little')
        print(f"Buffer LE is at 0x{buffer_addr:x}")

    if pc == START_ANGR:
        print(f"Start angr from 0x{pc:x}")
        res = do_angr(panda, env, pc) # Get solution from angr
        #res = "{l!\x00" # XXX: Debugging
        print("Solution:", res)

        buf = [bytes([ord(x)]) for x in res]
        buffer_addr_be = int.from_bytes((buffer_addr).to_bytes(4, byteorder='big'), byteorder='little')
        r = panda.virtual_memory_write(env, buffer_addr_be,  buf) # Write solution into buffer

        if r == -1: # XXX WHY DOES THIS FAIL?
            print("ERROR WRITING")
        d()

    return 0

@blocking
def run_foo():
    panda.revert_sync("root")
    panda.copy_to_guest("toy")
    res = panda.run_serial_cmd("toy/foo; echo \\\"Solved=$?\\\"")
    print("Result:", res)
    panda.stop_run()

panda.queue_async(run_foo)
panda.run()
