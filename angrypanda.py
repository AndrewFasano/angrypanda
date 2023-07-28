import capstone
import angr
import claripy
import logging
import itertools

from io import BytesIO
from pandare import PyPlugin

logging.basicConfig(format='%(levelname)-7s | %(asctime)-23s | %(name)-8s | %(message)s')
logger = logging.getLogger('angrypanda')
logger.setLevel('INFO')

class AngryPanda(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.syncd_memory_addrs = set()
        self.cpustate = None

        self.sym_buffers = []
        self.found_input = None # Dynamically computed during first run XXX move?

        # TODO, handle for more archs. This is just for debugging though
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    def angr_insn_exec(self, state):
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
        for i in self.md.disasm(op_bytes, state.inspect.instruction):
            print("[symex] 0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            break

    def mem_jit(self, state):
        '''
        Immediately before angr reads new data from memory, set a concrete value
        from PANDA, unless it's something we wanted to leave as symbolic

        Optimization: Only sync if we haven't already
        '''
        addr = state.inspect.mem_read_address
        read_len = state.inspect.mem_read_length

        assert(isinstance(addr, claripy.ast.bv.BV)), "Expected BVV in mem_jit"

        if addr.symbolic:
            possible_addrs = state.solver.eval_upto(addr, n=100)  # Get some potential addresses (TODO: how's this limit?)
            for potential_addr in possible_addrs:
                # Convert addr to a pointer (uint32_t), and read read_len bytes from it
                #potential_addr_int = int(''.join(map(str, potential_addr)), 2)  # convert tuple to binary and then to int
                #concrete_byte_val = self.panda.virtual_memory_read(self.cpustate, potential_addr_int, read_len)
                try:
                    concrete_byte_val = self.panda.virtual_memory_read(self.cpustate, potential_addr, read_len)
                except ValueError:
                    # Leave as symbolic??? What??
                    return

                # TODO is this all wrong?
                byte_int_val = int.from_bytes(concrete_byte_val, byteorder='big')
                bvv_val = claripy.BVV(byte_int_val, read_len*8)

                potential_addr_bvv = state.solver.BVV(potential_addr, addr.size())  # create BVV with the int
                state.memory.store(potential_addr_bvv, bvv_val, endness="Iend_BE")
                self.syncd_memory_addrs.add(potential_addr)
                return

        # Convert addr to a pointer (uint32_t), and read read_len bytes from it
        logger.debug(f"JIT sync {read_len} bytes of memory at 0x{(addr.concrete_value):x}")
        try:
            concrete_byte_val = self.panda.virtual_memory_read(self.cpustate, addr.concrete_value, read_len)
        except ValueError:
            print("Failed to read memory from panda at 0x%x" % addr.concrete_value)
            # Leave as symbolic??? What??
            return
        byte_int_val = int.from_bytes(concrete_byte_val, byteorder='big')
        bvv_val = claripy.BVV(byte_int_val, read_len*8)
        state.memory.store(addr, bvv_val, endness="Iend_BE")
        self.syncd_memory_addrs.add(addr.concrete_value)

    def should_mem_jit(self, state):
        '''
        Concretize address - if it's not in our memory map, then we need to mem_jit
        '''
        addr = state.inspect.mem_read_address
        if isinstance(addr, claripy.ast.bv.BV):
            if addr.symbolic:
                # XXX TODO
                return True
                for potential_addr in itertools.product(*[state.solver.eval_upto(b, 2**b.length) for b in addr.chop(8)]):
                    potential_addr_int = int(''.join(map(str, potential_addr)), 2)  # convert tuple to binary and then to int
                    potential_addr_bvv = state.solver.BVV(potential_addr_int, addr.size())  # create BVV with the int
                    if potential_addr.args[0] not in self.syncd_memory_addrs:
                        self.syncd_memory_addrs.add(potential_addr_bvv)
                        return True
                return False
            else:
                # Concrete address, extract int
                addr = addr.concrete_value
        elif isinstance(addr, int):
            addr = state.inspect.mem_read_address
        else:
            raise ValueError(f"Should_mem_jit got unexpected {type(addr)}")
        
        # Should be an int now?
        if addr not in self.syncd_memory_addrs:
            if addr not in self.sym_buffers:
                return True
            else:
                logger.info(f"Checked if angr should JIT sync memory at 0x{(addr):x}: Leave as symbolic")
        return False


    def call_jit(self, state):
        '''
        Just before angr does a call into not yet-JIT-ed memory, load 0x100 bytes there
        using our code_jit logic
        '''
        addr = state.inspect.function_address
        state.inspect.mem_read_address = state.solver.eval_one(addr)
        state.inspect.mem_read_length = 0x100
        self.code_jit(state)

    def should_call_jit(self, state):
        return True
        '''
        Before angr enters a call instruction, check if there's an instruction (4 bytes?) of data there
        '''
        addr = state.inspect.function_address
        addr_c = state.solver.eval(addr)
        if addr_c in self.syncd_code_addrs:
            return False
        else:
            self.syncd_code_addrs.add(addr_c)
            return True

    def code_jit(self, state):
        '''
        Immediately before angr parses a new block of code, set a concrete value from PANDA
        '''
        addr = state.inspect.mem_read_address #XXX: This returns an int not an object like normal
        max_read_length = state.inspect.mem_read_length
        concrete_byte_val = self.panda.virtual_memory_read(self.cpustate, addr, max_read_length)

        # Copy up to max_read_length bytes into angr's memory
        # If angr already has data somewhere in this space, don't replace it
        #XXX: Inefficient, should chunk
        for this_addr in range(addr, addr+max_read_length):
            if this_addr not in state.memory: # Found an object, write last chunk of data
                #state.memory.store(this_addr, concrete_byte_val[this_addr-addr], length=1, endness="Iend_BE")
                state.mem[this_addr].uint8_t = concrete_byte_val[this_addr-addr]
                self.syncd_memory_addrs.add(this_addr)

        """
        # Copy chunks of data that needs to go into angr
        def _store(base, start, end): # Copy data from panda's memory into angrs for this range
            byte_vals = int.from_bytes(concrete_byte_val[start-base:end-base], byteorder='big')
            state.memory.store(start, byte_vals, end-start)
            logger.debug(f"JIT store 0x{(end-start):x} bytes of code at 0x{start:x}")

        copy_start = None
        for this_addr in range(addr, addr+max_read_length):
            if this_addr in self.syncd_code_addrs: # Don't need this, it's in angr mem
                if copy_start is not None: # Copy from copy_start to here-1
                    _store(addr, copy_start, this_addr-1) # XXX: Don't store this_addr
                    copy_start = None
            else: # Not in angr mem
                if copy_start is None: # Start of mem we need to copy
                    copy_start = this_addr

        if copy_start: # Must copy last region if we end on memory that needs a copy
            if copy_start is not None:
                _store(addr, copy_start, this_addr) # XXX: Do store the last `this_addr`

        #concrete_byte_val = self.panda.virtual_memory_read(self.cpustate, addr, read_len)
        """

    def should_code_jit(self, state):
        '''
        Given an address and the (maximum) size of the code there,
        return true if any data in that range is missing from angr's memory
        '''
        base_addr = state.inspect.mem_read_address
        if not base_addr:
            return False
        max_length = state.inspect.mem_read_length
        logger.info(f"Evaluate need to JIT store any code from 0x{base_addr:x} to 0x{base_addr+max_length:x}")
        for addr in range(base_addr, base_addr+max_length):
            if addr not in self.syncd_memory_addrs:
                logger.debug(f"Need memory at 0x{addr:x}")
                return True

        return False


    @PyPlugin.ppp_export
    def run_symex(self, cpu, pc, find_addr, avoid_addrs, sym_buffers):
        '''
        sym_buffers should be a list (sizes?) of addresses
        to leave symbolic.  TODO: Can we specify sizes? registers?
        '''
        assert(self.cpustate is None), "Already mid-symex"
        self.cpustate = cpu
        self.sym_buffers = sym_buffers

        # Initialze angr - Place the next 0x100 bytes into meory from PC
        mem = self.panda.virtual_memory_read(cpu, pc, 0x100)
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
        for reg in self.panda.arch.registers.keys():
            val = self.panda.arch.get_reg(cpu, reg)
            #print(f"Setting register {reg} to {val:x}")
            setattr(start_state.regs, reg.lower(), val)

        #start_state.regs.eip = pc # Unnecessary with entry_point/base_addr?
        
        # Manually sync stack data
        #stack_data = self.panda.virtual_memory_read(self.cpustate, self.panda.arch.get_reg(self.cpustate, self.panda.arch.reg_sp), 0x100)
        #start_state.memory.store(start_state.regs.esp, stack_data, length=0x100, endness="Iend_BE")

        # Debugigng: print all instructions
        start_state.inspect.b('instruction', action=self.angr_insn_exec, when=angr.BP_BEFORE)

        # Whenever we read a symbolic value, use mem_read to find a concrete value
        start_state.inspect.b('mem_read', condition=self.should_mem_jit, action=self.mem_jit, when=angr.BP_BEFORE)

        # Copy code on demand as well
        start_state.inspect.b('vex_lift', condition=self.should_code_jit, action=self.code_jit, when=angr.BP_BEFORE)

        # When we hit a CALL, we'll need to copy code on demand as well
        start_state.inspect.b('call', condition=self.should_call_jit, action=self.call_jit, when=angr.BP_BEFORE)

        # In an angr simulation, try to find FIND_ADDR and avoid AVOID
        simgr = project.factory.simulation_manager(start_state)
        #simgr.explore(find=find_addr, avoid=avoid_addrs)
        simgr.run(until=lambda lpg: len(lpg.active) > 1)

        # Print all stash info - we have errored stashes and we want to know why
        for error in simgr.errored:
            print(f"Error occurred during execution of state {error.state}.")
            print(f"Error information: {error.error}")
            print(error.state.history.recent_ins_addrs)


        print(simgr)

        #assert(len(simgr.found)), f"Failed to find solution in {simgr}"
        #if len(simgr.errored):
        #    print(simgr.errored[0])

        '''
        final_state = simgr.found[0]
        # TODO: provide solution back to caller in a more versatile way
        # Constrain each character in solution to be ascii
        for buffer_addr in self.sym_buffers:
            for i in range(4):
                #byte = final_state.memory.load(buffer_addr+i, 1)
                byte = final_state.mem[buffer_addr+i].uint8_t 
                print(byte)
                final_state.solver.add(byte > 0x20)
                final_state.solver.add(byte < 0x7F)

        mem = final_state.memory.load(buffer_addr, 4)
        print(mem)
        soln = final_state.solver.eval(mem)
        # soln is a BVV, convert to string
        soln_s = ''.join([chr(x) for x in soln.chop(8)])

        print(f"Solution: 0x{soln:x} == \"{soln_s}\"")
        assert(sum([ord(x) for x in soln_s]) == 0x108), "Invalid solution" # DEBUG: test if result is correct

        return soln_s
        '''
        for state in simgr.active:
            constraints = state.solver.constraints
            print("For state %s, constraints are %s" % (state, constraints))

            for sym_buffer in sym_buffers:
                # Provide a concrete value for each sym_buffer
                mem = state.memory.load(sym_buffer, 4, disable_actions=True, inspect=False)
                res = state.solver.eval(mem)

                # Byte swap res
                res = int.from_bytes(res.to_bytes(4, byteorder='little'), byteorder='big')

                # Report the memory mapping in a more readable format
                print(f"\tSolution: set 4 bytes of memory at address 0x{sym_buffer:x} to 0x{res:x}")


        return simgr