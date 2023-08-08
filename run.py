#!/usr/bin/env python3

# Run a program in PANDA to a point. Then run in angr and transfer state
# on-demand to find an input that will reach a success message. Then place solution
# in the concrete PANDA execution's memory and confirm it works
# Similar to http://angr.io/blog/angr_symbion/ but going PANDA->ANGR->PANDA instead of ANGR->PANDA->ANGR

# TODO: Support for variable sized input buffers

import logging
from pandare import Panda, blocking
from angrypanda import AngryPanda

# Settings - It would be better do do these using line numbers but good enough for this PoC
BUFFER_SET = 0x8048557 # After malloc (add esp, 0x10)
START_ANGR = 0x804859e # After printf buffer contains (add esp, 0x10)
FIND_ADDR  = 0x80485e5 # Before print success (push eax=>s_success)
AVOID      = 0x80485f9 # Before print failure (push eax=>failure)
END_MAIN   = 0x8048611 # Main's ret (ret)

logging.basicConfig(format='%(levelname)-7s | %(asctime)-23s | %(name)-8s | %(message)s')
logger = logging.getLogger('run')
logger.setLevel('DEBUG')


panda = Panda(generic="i386")

panda.pyplugins.load(AngryPanda)

@panda.cb_start_block_exec
def sbe(cpu, tb):
    global buffer_addr, found_input
    pc = panda.current_pc(cpu)
    #func, line = addr_to_dbginfo(pc) # This is a bit slow
    #if func is not None:
    #    print(f"Executing basic block starting in function {func} at line {line}")

    if pc == BUFFER_SET: # When malloc returns, grab the address so we can keep it symbolic for later
        buffer_addr = panda.arch.get_reg(cpu, "eax")
        logger.info(f"Malloc'd buffer is at 0x{buffer_addr:x}")

        #elif func =="main" and line == 26:
    elif pc == START_ANGR:
        logger.info(f"Reached 0x{pc:x}: Starting ANGR")
        assert(buffer_addr is not None), "Unset buffer address"

        def _int_to_str(x):
            '''
            Convert an integer to a sequence of characters
            '''
            ret = ""
            s = hex(x)[2:] # Trim off 0x
            while len(s):
                ret += chr(int(s[:2], 16))
                s = s[2:]
            return ret

        # Switch into angr to find a solution
        simgr = panda.pyplugins.ppp.AngryPanda.run_symex(cpu, pc, [(buffer_addr, 4)])

        # Given the results,
        found_inputs = []
        for state in simgr.active:
            # Constrain each character in solution to be ascii
            for i in range(4):
                byte = state.memory.load(buffer_addr+i, 1, disable_actions=True, inspect=False)
                state.solver.add(byte > 0x20)
                state.solver.add(byte < 0x7F)

            mem = state.memory.load(buffer_addr, 4)
            soln = state.solver.eval(mem)
            buf = [bytes([ord(x)]) for x in soln]
            found_inputs.append(buf)

        if len(found_inputs):
            buf = found_inputs[0]
            panda.virtual_memory_write(cpu, buffer_addr,  buf)
            panda.disable_callback('sbe', forever=True)
        else:
            raise RuntimeError("Failed to find any results")

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
