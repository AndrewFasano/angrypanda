#!/usr/bin/env python3

# Run a program in PANDA to a point. Then run in angr and transfer state
# on-demand to find an input that will reach a success message. Then place solution
# in the concrete PANDA execution's memory and confirm it works
# Similar to http://angr.io/blog/angr_symbion/ but going PANDA->ANGR->PANDA instead of ANGR->PANDA->ANGR

# TODO: Support for variable sized input buffers

from sys import argv, stdout
from os import path
import capstone
import angr
import claripy
import struct
import logging

from pandare import Panda, blocking
from io import BytesIO
from ipdb import set_trace as d

logging.basicConfig(format='%(levelname)-7s | %(asctime)-23s | %(name)-8s | %(message)s')
logger = logging.getLogger('angrypanda')
logger.setLevel('DEBUG')

panda = Panda(generic="i386")

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
buffer_addr = None # Dynamically identified, address of buffer returned from malloc
found_input = None # Dynamically computed during first run

# Settings - It would be better do do these using line numbers but good enough for this PoC
BUFFER_SET = 0x8048557 # After malloc (add esp, 0x10)
START_ANGR = 0x804859e # After printf buffer contains (add esp, 0x10)
FIND_ADDR  = 0x80485e5 # Before print success (push eax=>s_success)
AVOID      = 0x80485f9 # Before print failure (push eax=>failure)
END_MAIN   = 0x8048611 # Main's ret (ret)

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

g_env = None
def mem_jit(state):
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
        le_int_val = int.from_bytes(concrete_byte_val, byteorder='little') # XXX: This is just for printing in the correct endianness
        logger.debug(f"JIT store {read_len} bytes to address 0x{addr_c:x}: 0x{le_int_val:x}")
        state.memory.store(addr_c, int_val, endness="Iend_BE") # Set the value - Don't flip endianness on store

def should_mem_jit(state):
    '''
    Concretize address - if it's not in our memory may, then we need to mem_jit
    '''
    l = state.inspect.mem_read_length
    addr = state.inspect.mem_read_address
    addr_c = state.solver.eval(addr)

    angr_mem = state.memory.mem.load_objects(addr_c, l)

    return len(angr_mem)==0

def call_jit(state):
    '''
    Just before angr does a call into not yet-JIT-ed memory, load 0x100 bytes there
    using our code_jit logic
    '''
    addr = state.inspect.function_address
    state.inspect.mem_read_address = state.solver.eval(addr)
    state.inspect.mem_read_length = 0x100
    code_jit(state)

def should_call_jit(state):
    '''
    Before angr enters a call instruction, check if there's an instruction (4 bytes?) of data there
    '''
    addr = state.inspect.function_address
    addr_c = state.solver.eval(addr)
    angr_mem = state.memory.mem.load_objects(addr_c, 4)
    return len(angr_mem)==0



def code_jit(state):
    '''
    Immediately before angr parses a new block of code, set a concrete value from PANDA
    '''
    addr = state.inspect.mem_read_address #XXX: This returns an int not an object like normal
    max_read_length = state.inspect.mem_read_length
    concrete_byte_val = panda.virtual_memory_read(g_env, addr, max_read_length)

    # Copy up to max_read_length bytes into angr's memory
    # If angr already has data somewhere in this space, don't replace it
    """
    #XXX: Inefficient, should chunk
    for this_addr in range(addr, addr+max_read_length):
        if this_addr not in state.memory: # Found an object, write last chunk of data
            state.memory.store(this_addr, concrete_byte_val[this_addr-addr], 1)
    """

    # Copy chunks of data that needs to go into angr
    def _store(base, start, end): # Copy data from panda's memory into angrs for this range
        byte_vals = int.from_bytes(concrete_byte_val[start-base:end-base], byteorder='big')
        state.memory.store(start, byte_vals, end-start)
        logger.debug(f"JIT store 0x{(end-start):x} bytes of code at 0x{start:x}")

    copy_start = None
    for this_addr in range(addr, addr+max_read_length):
        if this_addr in state.memory: # Don't need this, it's in angr mem
            if copy_start is not None: # Copy from copy_start to here-1
                _store(addr, copy_start, this_addr-1) # XXX: Don't store this_addr
                copy_start = None
        else: # Not in angr mem
            if copy_start is None: # Start of mem we need to copy
                copy_start = this_addr

    if copy_start: # Must copy last region if we end on memory that needs a copy
        if copy_start is not None:
            _store(addr, copy_start, this_addr) # XXX: Do store the last `this_addr`

    #concrete_byte_val = panda.virtual_memory_read(g_env, addr, read_len)

def should_code_jit(state):
    '''
    Given an address and the (maximum) size of the code there,
    return true if any data in that range is missing from angr's memory
    '''
    base_addr = state.inspect.mem_read_address
    if not base_addr:
        return False
    max_length = state.inspect.mem_read_length
    logger.debug(f"Evaluate need to JIT store any code from 0x{base_addr:x} to 0x{base_addr+max_length:x}")
    for addr in range(base_addr, base_addr+max_length):
        if addr not in state.memory:
            logger.debug(f"Need memory at 0x{addr:x}")
            return True

    return False

def do_angr(panda, env, pc):
    '''
    Given a panda state, do some symbolic execution with angr
    '''

    global g_env
    g_env = env

    # Initialze angr - Place the next 0x100 bytes into meory from PC
    mem = panda.virtual_memory_read(env, pc, 0x100)
    project = angr.Project(
                            BytesIO(mem),
                            main_opts={
                                'backend': 'blob',
                                'arch': 'i386',
                                'entry_point': pc,
                                'base_addr': pc,
                                }
                            )

    # Explorer
    start_state = project.factory.blank_state(addr=pc)
    #start_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY) # Silence warnings on symbolic data

    # Copy concrete registers into angr from panda
    for reg in panda.arch.registers.keys():
        val = panda.arch.get_reg(env, reg)
        setattr(start_state.regs, reg.lower(), val)
    # Debugigng: print all instructions
    start_state.inspect.b('instruction', action=angr_insn_exec, when=angr.BP_BEFORE)

    # Whenever we read a symbolic value, use mem_read to find a concrete value
    start_state.inspect.b('mem_read', condition=should_mem_jit, action=mem_jit, when=angr.BP_BEFORE)

    # Copy code on demand as well
    start_state.inspect.b('vex_lift', condition=should_code_jit, action=code_jit, when=angr.BP_BEFORE)

    # When we hit a CALL, we'll need to copy code on demand as well
    start_state.inspect.b('call', condition=should_call_jit, action=call_jit, when=angr.BP_BEFORE)

    # In an angr simulation, try to find FIND_ADDR and avoid AVOID
    simgr = project.factory.simulation_manager(start_state)
    simgr.explore(find=FIND_ADDR, avoid=[AVOID])

    assert(len(simgr.found)), d() #f"Failed to find solution in {simgr}"
    if len(simgr.errored):
        print(simgr.errored[0])

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
    #assert(sum([ord(x) for x in soln_s]) == 0x108), "Invalid solution"

    return soln_s

@panda.cb_before_block_exec #(procname="crackme") # TODO: fix procname filter, but it's unnecessary here
def bbe(env, tb):
    global buffer_addr, found_input
    pc = panda.current_pc(env)
    #func, line = addr_to_dbginfo(pc) # This is a bit slow
    #if func is not None:
    #    print(f"Executing basic block starting in function {func} at line {line}")

    if pc == BUFFER_SET: # When malloc returns, grab the address so we can keep it symbolic for later
        buffer_addr = panda.arch.get_reg(env, "eax")
        logger.info(f"Malloc'd buffer is at 0x{buffer_addr:x}")

        #elif func =="main" and line == 26:
    elif pc == START_ANGR:
        logger.info(f"Reached 0x{pc:x}: Starting ANGR")
        assert(buffer_addr is not None), "Unset buffer address"

        # Switch into angr to find a solution
        found_input = do_angr(panda, env, pc)

        buf = [bytes([ord(x)]) for x in found_input]
        r = panda.virtual_memory_write(env, buffer_addr,  buf)
        assert(r >= 0), f"Failed to write solution to memory"

        panda.disable_callback('bbe', forever=True)

@panda.queue_blocking
def run_crackme():
    '''
    Async function to revert the guest to a booted snapshot,
    copy the crackme directory in via a CD and then run the
    `crackme` program which has a function call
    '''
    panda.revert_sync("root")
    panda.copy_to_guest("crackme")
    concrete = panda.run_serial_cmd("crackme/crackme ABCD", no_timeout=True)
    print(f"Concrete output from PANDA with mutated memory: {repr(concrete)}")
    # Note buffer contains messgae uses orig buffer, but success happens because we changed it
    panda.end_analysis()

print("\n====== Begin first run =====")
panda.run()
assert(found_input), print("Failed first analysis - Try running again?")
print(f"====== Finished first run, found result {found_input} =====\n\n")


# Now let's run the whole thing with a valid solution
@blocking
def run_soln():
    global found_input
    panda.revert_sync("root")
    panda.copy_to_guest("crackme")
    concrete = panda.run_serial_cmd(f"crackme/crackme '{found_input}'")
    print(f"Concrete output from PANDA with soln: {repr(concrete)}")
    # Note buffer contains messgae uses orig buffer, but success happens because we changed it
    panda.end_analysis()

print(f"====== Starting second run with solution {found_input} =====")
panda.queue_async(run_soln)
panda.run()
print(f"====== Finished second run ====")
