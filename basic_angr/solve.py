#!/usr/bin/env python

import angr
import sys

from angr.storage.memory_object import SimMemoryObject, SimLabeledMemoryObject
from angr.state_plugins.plugin import SimStatePlugin
from angr.storage.memory_mixins import MemoryMixin
from angr import options

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

    def concrete_load(self, addr, size, writing=False, **kwargs) -> memoryview:
        print(f"Ignoring load of {addr:x}")
        return memoryview(b"")

    def _default_value(self, addr, size, name=None, inspect=True, events=True, key=None, **kwargs):
        print(f"Ignoring default for {addr:x}")
        return None

    def load(self, addr, size=None, **kwargs):
        if size:
            kwargs['size'] = size
        rv = super(PandaMemoryMixin, self).load(addr, **kwargs)
        print(f"L: {addr:x} {size:x} => {rv}")
        return rv

class PandaDefaultMemory(PandaMemoryMixin, angr.storage.memory_mixins.DefaultMemory):
    pass

class MyMemoryMixin(MemoryMixin):
    pass

class MyDefaultMemory(MyMemoryMixin, angr.storage.memory_mixins.DefaultMemory):
    pass

# Look at fauxware.c! This is the source code for a "faux firmware" (@zardus
# really likes the puns) that's meant to be a simple representation of a
# firmware that can authenticate users but also has a backdoor - the backdoor
# is that anybody who provides the string "SOSNEAKY" as their password will be
# automatically authenticated.


def basic_symbolic_execution():
    # We can use this as a basic demonstration of using angr for symbolic
    # execution. First, we load the binary into an angr project.

    p = angr.Project('fauxware', auto_load_libs=False)

    # Now, we want to construct a representation of symbolic program state.
    # SimState objects are what angr manipulates when it symbolically executes
    # binary code.
    # The entry_state constructor generates a SimState that is a very generic
    # representation of the possible program states at the program's entry
    # point. There are more constructors, like blank_state, which constructs a
    # "blank slate" state that specifies as little concrete data as possible,
    # or full_init_state, which performs a slow and pedantic initialization of
    # program state as it would execute through the dynamic loader.

    #state = p.factory.blank_state(plugins={'memory': PandaDefaultMemory(memory_id='mem', panda=None, panda_cpu=None, sym_buffers=None, stack_end=0x7ffffffffff0000)})
    #state = p.factory.blank_state(plugins={'memory': MyDefaultMemory()})
    #state = p.factory.blank_state(plugins={'memory': angr.storage.memory_mixins.DefaultMemory(memory_id='mem', stack_end=0x7ffffffffff0000)})
    state = p.factory.blank_state()
    state.register_plugin("memory", PandaDefaultMemory(memory_id='mem2', panda=None, panda_cpu=None, sym_buffers=None, stack_end=0x7ffffffffff0000))

    # Now, in order to manage the symbolic execution process from a very high
    # level, we have a SimulationManager. SimulationManager is just collections
    # of states with various tags attached with a number of convenient
    # interfaces for managing them.

    sm = p.factory.simulation_manager(state)

    # Uncomment the following line to spawn an IPython shell when the program
    # gets to this point so you can poke around at the four objects we just
    # constructed. Use tab-autocomplete and IPython's nifty feature where if
    # you stick a question mark after the name of a function or method and hit
    # enter, you are shown the documentation string for it.

    # import IPython; IPython.embed()

    # Now, we begin execution. This will symbolically execute the program until
    # we reach a branch statement for which both branches are satisfiable.

    sm.run(until=lambda sm_: len(sm_.active) > 1)
    if len(sm.errored):
        print(sm.errored[0])

    # If you look at the C code, you see that the first "if" statement that the
    # program can come across is comparing the result of the strcmp with the
    # backdoor password. So, we have halted execution with two states, each of
    # which has taken a different arm of that conditional branch. If you drop
    # an IPython shell here and examine sm.active[n].solver.constraints
    # you will see the encoding of the condition that was added to the state to
    # constrain it to going down this path, instead of the other one. These are
    # the constraints that will eventually be passed to our constraint solver
    # (z3) to produce a set of concrete inputs satisfying them.

    # As a matter of fact, we'll do that now.

    input_0 = sm.active[0].posix.dumps(0)
    input_1 = sm.active[1].posix.dumps(0)

    # We have used a utility function on the state's posix plugin to perform a
    # quick and dirty concretization of the content in file descriptor zero,
    # stdin. One of these strings should contain the substring "SOSNEAKY"!

    if b'SOSNEAKY' in input_0:
        return input_0
    else:
        return input_1

def test():
    r = basic_symbolic_execution()
    assert b'SOSNEAKY' in r

if __name__ == '__main__':
    sys.stdout.buffer.write(basic_symbolic_execution())

# You should be able to run this script and pipe its output to fauxware and
# fauxware will authenticate you.
