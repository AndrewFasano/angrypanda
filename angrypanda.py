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
    SUPPORTS_CONCRETE_LOAD = True
    def __init__(self, *args, **kwargs):
        self.panda = kwargs.pop('panda')
        self.cpu = kwargs.pop('panda_cpu')
        self.sym_buffers = kwargs.pop('sym_buffers') or []
        return super(PandaMemoryMixin, self).__init__(*args, **kwargs)

    @angr.SimStatePlugin.memo
    def copy(self,memo, *args, **kwargs):
        return PandaMemoryMixin(*args, panda=self.panda, panda_cpu=self.cpu, sym_buffers=self.sym_buffers, **kwargs)

    def panda_read(self, addr, size=None):
        for sym_buffer in self.sym_buffers:
            if sym_buffer >= addr and sym_buffer < addr + size:
                print(f"TODO: make read symbolic because {addr:x} is in {sym_buffer:x}")
                return None
            data = self.panda.virtual_memory_read(self.cpu, addr, size or 128)
            return data
        raise ValueError("No data")

    def concrete_load(self, addr, size, writing=False, **kwargs) -> memoryview:
        print(f"Concrete load mem for {size} bytes at {addr:x} with kwargs {kwargs}")
        try:
            rv = self.panda_read(addr, size) if size else None
            print(f"panda read returns:  {rv}")
            if rv:
                return memoryview(rv), memoryview(rv) # Concrete
            # Symbolic - TODO
            return memoryview(b""), memoryview(b"")

        except ValueError:
            # No data from panda, not symbolic either...
            return memoryview(b""), memoryview(b"")
    
    def load(self, addr, size=None, **kwargs):
        if size:
            kwargs['size'] = size
        return super(PandaMemoryMixin, self).load(addr, **kwargs)

class PandaDefaultMemory(PandaMemoryMixin, angr.storage.memory_mixins.DefaultFillerMixin): # XXX changed to DefaultFillerMixin from DefaultMemory which is bigger?
    pass

class PandaConcreteTarget():
    def __init__(self, *args, **kwargs):
        self.panda = kwargs.pop('panda')
        self.cpu = kwargs.pop('panda_cpu')
        self.sym_buffers = kwargs.pop('sym_buffers') or []
        self.state = kwargs.pop('state')
        self.id='panda_concrete_mem'

    def read_memory(self, addr, size, state=None):
        for sym_buffer in self.sym_buffers:
            if sym_buffer >= addr and sym_buffer < addr + size:
                print(f"TODO: make read symbolic because {addr:x} is in {sym_buffer:x}")

                if type(addr) is int:
                    name = f"{self.id}_{addr:x}"
                else:
                    name = 'mem'

                bits = size * self.state.arch.byte_width
                data = self.state.solver.Unconstrained(name, bits, key=None, inspect=False, events=False)
                print("Returning symbolic data", data)
                return data

            data = self.panda.virtual_memory_read(self.cpu, addr, size or 128)
            print(f"Success: read {size} bytes of memory at {addr:x} -> {data}")
            return data
        print(f"TODO: unable to read {size} bytes of memory at {addr:x}")
#################

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

        # TODO, handle for more archs. This is just for debugging though
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    def angr_insn_exec(self, state):
        """
        Debug callback - Print before each instruction we execute
        """
        op_bytes = state.memory.load(state.inspect.instruction, 32, disable_actions=True, inspect=False)
        print(f"Got memory at {state.inspect.instruction} for debug: {op_bytes}")
        for i in self.md.disasm(op_bytes, state.inspect.instruction):
            print("[symex] 0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            break

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
        start_state = project.factory.blank_state(addr=pc)
        project.concrete_target = PandaConcreteTarget(panda=self.panda, panda_cpu=cpu, sym_buffers=sym_buffers, state=start_state)

        # Copy concrete registers into angr from panda - Could also do in PandaConcreteTarget?
        for reg in self.panda.arch.registers.keys():
            val = self.panda.arch.get_reg(cpu, reg)
            #print(f"Setting register {reg} to {val:x}")
            setattr(start_state.regs, reg.lower(), val)

        # XXX there are more registers...
        #start_state.regs.ss = self.panda.env_ptr.ss

        # Debugigng: print all instructions
        #start_state.inspect.b('instruction', action=self.angr_insn_exec, when=angr.BP_BEFORE)

        # Run symex until we end up with multiple states as specified in self.rununtil
        simgr = project.factory.simulation_manager(start_state)
        simgr.run(until=self.rununtil)

        # Print all stash info - we have errored stashes and we want to know why
        for error in simgr.errored:
            print(f"Error occurred during execution of state {error.state}.")
            print(f"Error information: {error.error}")
            print(error.state.history.recent_ins_addrs)


        print(simgr)

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