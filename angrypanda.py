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

class PandaConcreteTarget():
    def __init__(self, *args, **kwargs):
        self.panda = kwargs.pop('panda')
        self.cpu = kwargs.pop('panda_cpu')
        self.state = kwargs.pop('state')
        self.id='panda_concrete_mem'

    def read_memory(self, addr, size, state=None) -> bytes:
        # Read concrete data
        try:
            conc = self.panda.virtual_memory_read(self.cpu, addr, size)
        except ValueError:
            raise ValueError(f"Unable to read concrete memory at {addr:x}")
        return conc

# How many blocks do we execute before giving up?
# If we have identified multiple states, we can stop sooner with the MULTISTATE limit
MULTISTATE_RUNCOUNT = 10
ONESTATE_RUNCOUNT = 100

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
        print(f"Got memory at {state.inspect.instruction:x} for debug: {op_bytes}")
        for i in self.md.disasm(op_bytes, state.inspect.instruction):
            print("[symex] 0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            break

    def rununtil(self, state):
        # Stepping terminates when this fn returns True
        #print(f"Check rununtil with len active states: {len(state.active)}, runcount {self.runcount}, multistate_runcount {self.multistate_runcount}")
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
    def run_symex(self, cpu, pc):
        assert(self.cpustate is None), "Already mid-symex"
        self.cpustate = cpu

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
        project.concrete_target = PandaConcreteTarget(panda=self.panda, panda_cpu=cpu, state=start_state)

        # Create an instance of the SpecialFillerMixin, providing the custom fill function
        #special_filler = angr.storage.memory_mixins.SpecialFillerMixin(start_state.memory)
        #special_filler.special_fill = custom_fill

        ## Optionally, you can replace the memory plugin with your special filler instance
        #start_state.register_plugin('memory', special_filler)
        
        #start_state.register_plugin('memory', PandaDefaultMemory(memory_id='mem',
        #                                                        panda=self.panda,
        #                                                        panda_cpu=cpu,

        #import ipdb
        #ipdb.set_trace()

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
        return simgr