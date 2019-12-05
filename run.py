#!/usr/bin/env python3

# Run a program in PANDA to a point. Then run in angr and transfer state
# on-demand to find an input that will reach a success message. Then place solution
# in the concrete PANDA execution's memory and confirm it works
# Similar to http://angr.io/blog/angr_symbion/ but going PANDA->ANGR->PANDA instead of ANGR->PANDA->ANGR

# TODO: Support for longer input buffers
#       JIT mapping of code buffers

from sys import argv, stdout
from os import path
import capstone
import angr
import claripy
import struct
import logging

from panda import Panda, ffi, blocking
from panda.x86.helper import *
from io import BytesIO
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from ipdb import set_trace as d

panda = Panda(generic="i386")

logging.basicConfig(format='%(levelname)-7s | %(asctime)-23s | %(name)-8s | %(message)s')
logger = logging.getLogger('angrypanda')
logger.setLevel('DEBUG')
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
progname="crackme"
buffer_addr = None # Dynamically identified, address of buffer returned from malloc
found_input = None # Dynamically computed during first run
g_env = None # PANDA environment as a global

BUFFER_SET = 0x804850f # After malloc
START_ANGR = 0x8048554 # After buf is populated
FIND_ADDR  = 0x8048589 # Before print success
AVOID      = 0x80485a0 # Before print failure
END_MAIN   = 0x80485b6 # Main's ret

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

def int_to_str(x):
    '''
    Convert an integer to a sequence of characters
    '''
    ret = ""
    s = hex(x)[2:] # Trim off 0x
    while len(s):
        ret += chr(int(s[:2], 16))
        s = s[2:]
    return ret

def jit_store(state):
    '''
    Immediately before angr reads new data from memory,
    set a concrete value from PANDA, unless it's in the buffer we want to be
    symbolic
    '''
    addr = state.inspect.mem_read_address
    assert(addr.concrete), "Symbolic address is being read"
    assert(addr.op == 'BVV'), f"Unknown address op type: {addr.op}"
    addr_c = addr.args[0] # Concrete value of address

    read_len = state.inspect.mem_read_length
    concrete_byte_val = panda.virtual_memory_read(g_env, addr_c, read_len)
    byte_int_val = int.from_bytes(concrete_byte_val, byteorder='big') # XXX: Never flip endianness here so we mask correctly

    assert(read_len <= 4), "Unsupported read of multiple bytes"
    int_val = byte_int_val & (0xFFFFFFFF>>(4-read_len))               # If we flipped endianness, this would be backwards

    assert(buffer_addr is not None), "Buffer address is unset"
    if addr_c in range(buffer_addr, buffer_addr+4):
        logger.info(f"Create unconstrainted symbolic data of {read_len} bytes at address 0x{addr_c:x}. (Concrete value was 0x{int_val:x})")
    else:
        # This is just for printing in the correct endianness
        le_int_val = int.from_bytes(concrete_byte_val, byteorder='little')
        logger.debug(f"JIT store {read_len} bytes to address 0x{addr_c:x}: 0x{le_int_val:x}")
        # Now actually store the data
        state.memory.store(addr_c, int_val, endness="Iend_BE") # Set the value - Don't flip endianness on store

def do_jit(state):
    '''
    Concretize address - if it's not in our memory may, then we need to jit_store
    '''
    l = state.inspect.mem_read_length
    addr = state.inspect.mem_read_address
    addr_c = state.solver.eval(addr)

    angr_mem = state.memory.mem.load_objects(addr_c, l)

    return len(angr_mem)==0

def do_angr(panda, env, pc):
    '''
    Given a panda state, do some symbolic execution with angr
    '''
    global g_env
    g_env = env

    # Initialze angr - Place this function into memory as shellcode
    mem = panda.virtual_memory_read(env, pc, END_MAIN-pc)
    project = angr.load_shellcode(mem, arch='i386', load_address=pc)

    # Explore
    start_state = project.factory.blank_state(addr=pc)
    start_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY) # Silence warnings on symbolic data

    # Copy concrete registers into angr from panda
    for (angr_reg, panda_reg) in zip([x.lower() for x in registers.keys()], registers.values()):
        val = env.env_ptr.regs[panda_reg]
        setattr(start_state.regs, angr_reg, val)

    # Debugigng: print all instructions
    #start_state.inspect.b('instruction', action=angr_insn_exec, when=angr.BP_BEFORE)

    # Whenever we read a symbolic value, use mem_read to find a concrete value
    start_state.inspect.b('mem_read', condition=do_jit, action=jit_store, when=angr.BP_BEFORE)

    # In an angr simulation, try to find FIND_ADDR and avoid AVOID
    simgr = project.factory.simulation_manager(start_state)
    simgr.explore(find=FIND_ADDR, avoid=[AVOID])
    assert(len(simgr.found)), d() #f"Failed to find solution in {simgr}"

    final_state = simgr.found[0]
    # Constrain each character in solution to be ascii
    for i in range(4):
        byte = final_state.memory.load(buffer_addr+i, 1)
        final_state.solver.add(byte > 0x20)
        final_state.solver.add(byte < 0x7F)

    mem = final_state.memory.load(buffer_addr, 4)
    soln = final_state.solver.eval(mem)
    soln_s = int_to_str(soln)

    print(f"Solution: 0x{soln:x} == \"{soln_s}\"")
    assert(sum([ord(x) for x in soln_s]) == 0x108), "Invalid solution"

    return soln_s

@panda.cb_before_block_exec(procname=progname)
def bbe(env, tb):
    global buffer_addr, found_input
    pc = panda.current_pc(env)

    if pc == BUFFER_SET:
        buffer_addr = env.env_ptr.regs[R_EAX]
        logger.info(f"Malloc'd buffer is at 0x{buffer_addr:x}")

    elif pc == START_ANGR:
        logger.info(f"Reached 0x{pc:x}: Starting ANGR")
        assert(buffer_addr is not None), "Unset buffer address"

        # Switch into angr to find a solution
        found_input = do_angr(panda, env, pc)

        print(f"Placing solution \"{found_input}\" into memory at 0x{buffer_addr:x}") # XXX is that big endian?
        buf = [bytes([ord(x)]) for x in found_input]
        r = panda.virtual_memory_write(env, buffer_addr,  buf)
        assert(r >= 0), f"Failed to write solution to memory"

        panda.disable_callback('bbe', forever=True)

    return 0

@blocking
def run_crackme():
    '''
    Async function to revert the guest to a booted snapshot,
    copy the toy directory in via a CD and then run the 
    `crackme` program
    '''
    panda.revert_sync("root")
    panda.copy_to_guest("toy")
    concrete = panda.run_serial_cmd(f"toy/{progname} ABCD", no_timeout=True)
    print(f"Concrete output from PANDA with mutated memory: {repr(concrete)}")
    # Note buffer contains messgae uses orig buffer, but success happens because we changed it
    panda.end_analysis()

print("\n====== Begin first run =====")
panda.queue_async(run_crackme)
panda.run()
assert(found_input), print("Failed first analysis")
print(f"====== Finished first run, found result {found_input} =====\n\n")


# Now let's run the whole thing with a valid solution
@blocking
def run_soln():
    global found_input
    panda.revert_sync("root")
    panda.copy_to_guest("toy")
    concrete = panda.run_serial_cmd(f"toy/crackme '{found_input}'")
    print(f"Concrete output from PANDA with soln: {repr(concrete)}")
    # Note buffer contains messgae uses orig buffer, but success happens because we changed it
    panda.end_analysis()

print(f"====== Starting second run with solution {found_input} =====")
panda.queue_async(run_soln)
panda.run()
print(f"====== Finished second run ====")
