import capstone
import angr
import claripy
import logging
import itertools

from io import BytesIO
from pandare import PyPlugin

from angr.storage.memory_object import SimMemoryObject, SimLabeledMemoryObject
from angr.state_plugins.plugin import SimStatePlugin
from angr.storage.memory_mixins import MemoryMixin
from angr import options

logging.basicConfig(format='%(levelname)-7s | %(asctime)-23s | %(name)-8s | %(message)s')
logger = logging.getLogger('angrypanda')
logger.setLevel('INFO')

#################
class PandaMemoryMixin(MemoryMixin):
    #SUPPORTS_CONCRETE_LOAD = True
    def __init__(self, *args, **kwargs):
        self.panda = kwargs.pop('panda')
        self.cpu = kwargs.pop('panda_cpu')
        self.sym_buffers = kwargs.pop('sym_buffers') or []
        return super(PandaMemoryMixin, self).__init__(*args, **kwargs)

    @angr.SimStatePlugin.memo
    def copy(self,memo):
        return PandaMemoryMixin(panda=self.panda, panda_cpu=self.cpu, sym_buffers=self.sym_buffers)

    def panda_read(self, addr, size=None):
        for sym_buffer in self.sym_buffers:
            if sym_buffer >= addr and sym_buffer < addr + size:
                return None
            data = self.panda.virtual_memory_read(self.cpu, addr, size or 128)
            return data
        return None
    
    def load(self, addr, size=None, **kwargs):
        # Only try to load if the address is concrete
        if isinstance(addr, claripy.ast.bv.BV):
            if addr.symbolic:
                print(f"Load memory from symbolic {addr} of size {size}")
                # Fallback to default
                kwargs['size'] = size
                rv = super(PandaMemoryMixin, self).load(addr, **kwargs)

                # Now write our concrete data into angr's state
                super(PandaMemoryMixin, self).store(addr, rv, endness="Iend_BE")

                print(f"\tRV: {rv}, type {type(rv)}")
                return rv
            else:
                addr = addr.concrete

        if isinstance(addr, int): 
                print(f"Load memory from {addr:x} of size {size}")
                try:
                    rv = self.panda_read(addr, size) if size else None
                except ValueError:
                    print(f"Panda failed to read memory at {addr:x}")
                    # Default handler - probably symbolic? Not sure
                    return super(PandaMemoryMixin, self).load(addr, **kwargs)

                if rv:
                    # We managed to read data from PANDA - great
                    result = claripy.Concat(*[claripy.BVV(byte, 8) for byte in rv]) # Endian seems right
                    print(f"PANDA returns {result}")
                    return result
                else:
                    # IF we get here, we want a symbolic value?
                    print(f"No panda data for {addr:x} - XXX Symbolic!?")
                    #r = self.state.solver.Unconstrained(f'angrypanda_{addr:x}', bits)
                    #return DefaultFillerMixin._default_value(self, addr, size, name=None, inspect=True, events=True, key=None, fill_missing = True)

                    # Try just using the default filler which will warn?
                    kwargs['inspect'] = False
                    kwargs['events'] = False
                    kwargs['size'] = size
                    rv = super(PandaMemoryMixin, self).load(addr, **kwargs)
                    return rv
        else:
            print("What:", type(addr))



class PandaDefaultMemory(PandaMemoryMixin, angr.storage.memory_mixins.DefaultMemory):
    pass


class SimplePandaMemoryMixin(MemoryMixin):
    def __init__(self, *args, **kwargs):
        self.panda = kwargs.pop('panda')
        self.cpu = kwargs.pop('panda_cpu')
        self.sym_buffers = kwargs.pop('sym_buffers') or []
        self._store = kwargs.pop('store', None) or {}
        return super(SimplePandaMemoryMixin, self).__init__(*args, **kwargs)

    def load(self, key, none_if_missing=False, **kwargs):
        print(f"Load from {key}")
        if key in self._store:
            return self._store[key].value

        # If key not in store we'll use panda
        if isinstance(key, claripy.ast.bv.BV):
            if key.symbolic:
                raise ValueError("Symbolic memory read")
            else:
                key = key.concrete
        assert(isinstance(key, int)), f"Expected int, got {type(key)}"
        self.panda.virtual_memory_read(self.cpu, key, 1)

    def store(self, key, data, type_=None, **kwargs):
        print(f"Store {key}={data}")
        self._store[key] = (type_, data)

    @angr.SimStatePlugin.memo
    def copy(self,memo):
        return SimplePandaMemoryMixin(panda=self.panda, panda_cpu=self.cpu, sym_buffers=self.sym_buffers)

    def __str__(self):
        return "\n".join([f"{k}: {v.value} ({v.type})" for k, v in self._store.items()])

class SimplePandaDefaultMemory(SimplePandaMemoryMixin):
    pass
#################

    
    def _default_value(
        self, addr, size, name=None, inspect=True, events=True, key=None, fill_missing: bool = True, **kwargs
    ):
        print(f"Custom default value for {size} bytes at {addr:x}")
        mem = self.read_memory(addr, size)
        if mem:
            endness = kwargs["endness"]
            bvv = self.state.solver.BVV(mem)
            return bvv if endness == "Iend_BE" else bvv.reversed

        # XXX: Unconstrained - original default handling from default_filler_mixin
        bits = size * self.state.arch.byte_width

        if self.category == "reg" and type(addr) is int and addr == self.state.arch.ip_offset:
            # short-circuit this pathological case
            return self.state.solver.BVV(0, self.state.arch.bits)

        is_mem = (
            self.category == "mem"
            and options.ZERO_FILL_UNCONSTRAINED_MEMORY not in self.state.options
            and options.SYMBOL_FILL_UNCONSTRAINED_MEMORY not in self.state.options
        )
        is_reg = (
            self.category == "reg"
            and options.ZERO_FILL_UNCONSTRAINED_REGISTERS not in self.state.options
            and options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS not in self.state.options
        )
        if type(addr) is int and (is_mem or is_reg):
            if is_mem:
                refplace_int = self.state.solver.eval(self.state._ip)
                if self.state.project:
                    refplace_str = self.state.project.loader.describe_addr(refplace_int)
                else:
                    refplace_str = "unknown"
                logger.warning(
                    "Filling memory at %#x with %d unconstrained bytes referenced from %#x (%s)",
                    addr,
                    size,
                    refplace_int,
                    refplace_str,
                )
            else:
                if addr == self.state.arch.ip_offset:
                    refplace_int = 0
                    refplace_str = "symbolic"
                else:
                    refplace_int = self.state.solver.eval(self.state._ip)
                    if self.state.project:
                        refplace_str = self.state.project.loader.describe_addr(refplace_int)
                    else:
                        refplace_str = "unknown"
                reg_str = self.state.arch.translate_register_name(addr, size=size)
                logger.warning(
                    "Filling register %s with %d unconstrained bytes referenced from %#x (%s)",
                    reg_str,
                    size,
                    refplace_int,
                    refplace_str,
                )
                if name is None and not reg_str.isdigit():
                    name = "reg_" + reg_str

        if name is None:
            if type(addr) is int:
                name = f"{self.id}_{addr:x}"
            else:
                name = self.category

        r = self.state.solver.Unconstrained(name, bits, key=key, inspect=inspect, events=events)

        return r



'''
# Monkeypatch angr to replace default filler with panda
def custom_default_value(
    self, addr, size, name=None, inspect=True, events=True, key=None, fill_missing: bool = True, **kwargs
):
    print("Monkeypatch running for addr 0x%x" % addr)
    # Check if PANDA is available
    if hasattr(self.state, 'angrypanda') and self.state.angrypanda is not None:
        # Read from PANDA todo: handle sym buffers
        mem = self.state.angrypanda.panda.vritual_memory_read(self.state.angrypanda.cpustate, addr, size)
        endness = kwargs["endness"]
        bvv = self.state.solver.BVV(mem)
        return bvv if endness == "Iend_BE" else bvv.reversed

    else:
        raise RuntimeError("??")
    # If PANDA is not available, fall back to the original behavior
    #return original_default_value(self, addr, size, name, inspect, events, key, fill_missing, **kwargs)

# Save a reference to the original method
#original_default_value = DefaultFillerMixin._default_value

# Replace the original method with the custom function
import types
DefaultFillerMixin._default_value = types.MethodType(custom_default_value, DefaultFillerMixin)
'''

'''
#from angr.storage.memory import SimMemory
from angr.storage.memory_mixins import MemoryMixin

synchronization_map = {}
def jit_synchronized_load_memory(self, addr, **kwargs):
    # Check if this memory region has been synchronized
    print(f"Check if memory at 0x{addr:x} has been synchronized")
    #if addr not in synchronization_map:
    #    # Synchronize memory from PANDA
    #    concrete_data = panda_read_memory(addr, size)
    #    # Write to angr's memory
    #    self.store(addr, concrete_data)
    #    # Update synchronization map
    #    synchronization_map[addr] = size

    # Call the original method to load the memory
    return original_load_memory(self, addr, **kwargs)

# Save the original method
original_load_memory = MemoryMixin.load
# Patch the method
MemoryMixin.load = jit_synchronized_load_memory
'''


# How many blocks do we execute before giving up?
# If we have identified multiple states, we can stop sooner with the MULTISTATE limit
MULTISTATE_RUNCOUNT = 5
ONESTATE_RUNCOUNT = 20

class AngryPanda(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.syncd_memory_addrs = set()
        self.cpustate = None
        self.multistate_runcount = 0
        self.runcount = 0

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

        # Sanity check: read panda memory vs angr memory
        if False:
            print("Panda memory at 0x%x: %s" % (state.inspect.instruction, self.panda.virtual_memory_read(self.cpustate, state.inspect.instruction, 8)))

            # Also print the nexxt few bytes:
            print("\t", end="")
            for x in ops:
                print("%02x" % x, end="")

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
                
                # Symbolic: handled first potential address, now bail(?)
                return

        # Non-symbolic
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

    def should_ret_jit(self, state):
        # Before we execute a ret, make sure there's code at the address
        return True

    def ret_jit(self, state):
        '''
        Just before angr does a ret into not yet-JIT-ed memory, load 0x100 bytes there
        using our mem_sync logic
        '''
        retaddr = state.mem[state.regs.sp].uint32_t.resolved # Returns a BVV
        retaddr_c = state.solver.eval_one(retaddr) # Convert to int

        # Debug print
        cur_pc = state.inspect.function_address
        cur_pc_c = state.solver.eval_one(cur_pc)
        print(f"Ret JIT from fn at {cur_pc_c:x} goes to {retaddr_c:x}")

        self.mem_sync(state, retaddr_c, 0x1000)

    def call_jit(self, state):
        '''
        Just before angr does a call into not yet-JIT-ed memory, load 0x100 bytes there
        using our mem_sync logic
        '''
        addr = state.inspect.function_address
        addr_c = state.solver.eval_one(addr) # This is the adress of the target fn
        #state.inspect.mem_read_address = addr_c
        #og_len = state.inspect.mem_read_length
        #state.inspect.mem_read_length = 0x1000
        #print(f"\nCall jit at {addr_c:x} to {addr_c+og_len:x}")

        # For each field in the state, print it
        '''
        for f in dir(state.inspect):
            val = getattr(state.inspect, f, None)
            if isinstance(val, int):
                val = hex(val)
            print(f"{f}: {val}")
        '''
        self.mem_sync(state, addr_c, 0x1000)

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

    def mem_sync(self, state, addr, max_read_length):
        concrete_byte_val = self.panda.virtual_memory_read(self.cpustate, addr, max_read_length)

        #print(f"Code JIT ends at {addr+max_read_length:x}")

        # Copy up to max_read_length bytes into angr's memory
        # If angr already has data somewhere in this space, don't replace it
        #XXX: Inefficient, should chunk
        for this_addr in range(addr, addr+max_read_length):
            if this_addr not in self.syncd_memory_addrs: # Found an object, write last chunk of data
                #state.memory.store(this_addr, concrete_byte_val[this_addr-addr], length=1, endness="Iend_BE")
                state.mem[this_addr].uint8_t = concrete_byte_val[this_addr-addr]
                self.syncd_memory_addrs.add(this_addr)
                #print(f"jit code[{this_addr:x}]= {concrete_byte_val[this_addr-addr]}")

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

    def old_code_jit(self, state):
        '''
        Immediately before angr parses a new block of code, set a concrete value from PANDA
        '''
        addr = state.inspect.mem_read_address #XXX: This returns an int not an object like normal
        max_read_length = state.inspect.mem_read_length

        self.mem_sync(state, addr, max_read_length)

    def OLDshould_code_jit(self, state):
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

    def rununtil(self, state):
        # Stepping terminates when this fn returns True
        print(f"Check rununtil with len active states: {len(state.active)}, runcount {self.runcount}, multistate_runcount {self.multistate_runcount}")
        if len(state.active) > 1:
            self.multistate_runcount += 1
            if self.multistate_runcount > MULTISTATE_RUNCOUNT:
                print("Terminate because multistate runcount")
                return True

        self.runcount += 1
        if self.runcount > ONESTATE_RUNCOUNT:
            print("Terminate because one state runcount")
            return True
        return False


    def should_code_jit(self, state):
        base_addr = state.inspect.address
        if not base_addr:
            return False
        max_length = state.inspect.mem_read_length or 0x1000 # XXX probably always the constant?
        logger.info(f"Evaluate need to JIT store any code from 0x{base_addr:x} to 0x{base_addr+max_length:x}")
        for addr in range(base_addr, base_addr+max_length):
            if addr not in self.syncd_memory_addrs:
                logger.debug(f"Need code at 0x{addr:x}")
                return True
        return False

    def code_jit(self, state):
        '''
        Immediately before angr parses a new block of code, set a concrete value from PANDA
        '''
        addr = state.inspect.address
        max_read_length = state.inspect.mem_read_length or 0x20

        # XXX disabled helper call to use code below instead
        #self.mem_sync(state, addr, max_read_length)

        concrete_byte_val = self.panda.virtual_memory_read(self.cpustate, addr, max_read_length)

        # Disassemble with capstone for debug
        for i in self.md.disasm(concrete_byte_val, addr):
            print("[symex: concrete from 0x%x] 0x%x:\t%s\t%s" %(addr, i.address, i.mnemonic, i.op_str))

        # Copy up to max_read_length bytes into angr's memory
        #for this_addr in range(addr, addr+max_read_length):
        #    if this_addr not in self.syncd_memory_addrs: # Found an object, write last chunk of data
        #        #state.memory.store(this_addr, concrete_byte_val[this_addr-addr], length=1, endness="Iend_BE")
        #        state.mem[this_addr].uint8_t = concrete_byte_val[this_addr-addr]
        #        self.syncd_memory_addrs.add(this_addr)
        #        print(f"jit code[{this_addr:x}]= {concrete_byte_val[this_addr-addr]:x}")

        # Assuming concrete_byte_val is a bytes object containing the raw bytes to be copied
        # and that you're working with a little-endian architecture like x86

        debug = False
        for i in range(max_read_length):
            this_addr = addr + i
            if this_addr not in self.syncd_memory_addrs:
                byte_val = concrete_byte_val[i]
                bv_val = claripy.BVV(byte_val, 8) 
                state.memory.store(this_addr, bv_val, endness=state.arch.memory_endness)
                self.syncd_memory_addrs.add(this_addr)
                print(f"jit code[{this_addr:x}]= {byte_val:x}")
                if this_addr == 0x80484b6:
                    debug = True

        if debug:
            import ipdb
            print("JIT COPY BuGGY BLOCK")
            ipdb.set_trace()

    def code_jit_after(self, state):
        addr = state.inspect.address
        if addr == 0x80484b6:
            import ipdb
            print("JIT COPY post-BuGGY BLOCK")
            ipdb.set_trace()

    @PyPlugin.ppp_export
    def run_symex(self, cpu, pc, sym_buffers):
        '''
        sym_buffers should be a list (sizes?) of addresses
        to leave symbolic.  TODO: Can we specify sizes? registers?
        '''
        assert(self.cpustate is None), "Already mid-symex"
        self.cpustate = cpu
        self.sym_buffers = sym_buffers

        # Initialze angr - Place the next 0x100 bytes into meory from PC
        mem = self.panda.virtual_memory_read(cpu, pc, 0x200)
        project = angr.Project(
                                BytesIO(mem),
                                main_opts={
                                    'backend': 'blob',
                                    'arch': 'i386',
                                    'entry_point': pc,
                                    'base_addr': pc,
                                    }
                                )

        # Create state with custom plugin for memory accesses
        start_state = project.factory.blank_state(addr=pc,
                                                  plugins={'memory': PandaDefaultMemory(memory_id='mem',
                                                                                        panda=self.panda,
                                                                                        panda_cpu=cpu,
                                                                                        sym_buffers=sym_buffers)})

        # Copy concrete registers into angr from panda - Could also do in PandaConcreteTarget?
        for reg in self.panda.arch.registers.keys():
            val = self.panda.arch.get_reg(cpu, reg)
            #print(f"Setting register {reg} to {val:x}")
            setattr(start_state.regs, reg.lower(), val)

        # Debugigng: print all instructions
        start_state.inspect.b('instruction', action=self.angr_insn_exec, when=angr.BP_BEFORE)

        # Whenever we read a symbolic value, use mem_read to find a concrete value
        #start_state.inspect.b('mem_read', condition=self.should_mem_jit, action=self.mem_jit, when=angr.BP_BEFORE)

        # Copy code on demand as well
        #start_state.inspect.b('vex_lift', condition=self.should_code_jit, action=self.code_jit, when=angr.BP_BEFORE)

        # When we hit a CALL, we'll need to copy code on demand as well
        #start_state.inspect.b('call', condition=self.should_call_jit, action=self.call_jit, when=angr.BP_BEFORE)

        # When we hit a RET, we'll need to copy code on demand as well
        #start_state.inspect.b('return', condition=self.should_ret_jit, action=self.ret_jit, when=angr.BP_BEFORE)

        # Whenever we're about to load a new block of code, sync it - handles call/ret/lift etc
        #start_state.inspect.b('irsb', condition=self.should_code_jit, action=self.code_jit, when=angr.BP_BEFORE)
        #start_state.inspect.b('irsb', action=self.code_jit_after, when=angr.BP_AFTER)

        # In an angr simulation, try to find FIND_ADDR and avoid AVOID
        simgr = project.factory.simulation_manager(start_state)
        #simgr.explore(find=find_addr, avoid=avoid_addrs)
        print("Do simgr run", simgr)
        simgr.run(until=self.rununtil)

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