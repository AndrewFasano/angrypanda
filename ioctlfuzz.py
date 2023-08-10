from pandare import PyPlugin, blocking
from time import sleep
from threading import Lock
from sys import stdout

N_BLOCKS = 10

class IoctlFuzz(PyPlugin):
    def __init__(self, panda):
        self.panda = panda

        self.ioctls = {} # (ioctl_num, fname) -> data
        self.fuzzing = None # Set to an (ioctl, fname) key when we're fuzzing it
        self.panda.enable_precise_pc()
        self.fuzz_targets = [] # (ioctl_num, fname) tuples. Either or both may be None for a wildcard

        @panda.ppp("syscalls2", "on_sys_ioctl_enter")
        def before_ioctl(cpu, pc, fd, request, argp):
            # Identify key for this ioctl and take snapshot if it's new
            fname = panda.get_file_name(cpu, fd)
            k = (request, fname.decode())

            if k not in self.ioctls:
                print(f"Identified new IOCTL enter at {pc:x} with fname {fname}. Key {k}")
                self.ioctls[k] = {
                    "traces": {}, # trace -> set of rvs
                    "cur_rv": None, # Current return value
                    "cur_trace": [], # Current trace
                    "ret_addr": pc+2,
                    "enabled": True,
                    "active": False,
                    "q": self.make_queue(),
                    "snapshot": f"ioctl_{k[0]}_{k[1]}",
                }
                self.panda.snap(self.ioctls[k]["snapshot"])


                # Register a hook for the ioctl return - note we *don't* use sc2 on_ioctl_return
                # because we need this hook to trigger after we do a snapshot restore and sc2 won't
                # setup the return callback when it misses the enter with our snapshot
                @panda.hook(pc+2)
                def first_hook(cpu, tb, h):
                    rv = panda.arch.get_retval(cpu, convention="syscall")
                    if rv >= 0:
                        # No error - no need to fuzz
                        self.ioctls[k]['enabled'] = False
                        h.enabled = False
                        return

                    # Check if we should start fuzzing now
                    start_fuzz = (request, fname) in self.fuzz_targets or \
                                 (request, None) in self.fuzz_targets or \
                                 (None, fname) in self.fuzz_targets or \
                                 (None, None) in self.fuzz_targets

                    if not self.ioctls[k]['active'] and start_fuzz and not self.fuzzing:
                        print("[main] Start fuzzing")
                        self.fuzzing = k

                    if self.fuzzing == k:
                        # We're fuzzing and we just hit the syscall return - set the retval and initialze our post-ioctl trace
                        # If we're out of things to fuzz, report results and allow guest to continue execution
                        if not len(self.ioctls[k]['q']):
                            # Nothing left to fuzz here ... continue?
                            print(f"Finished fuzzing ioctl {self.fuzzing}")
                            self.ioctls[k]['enabled'] = False
                            # Dump results
                            self.dump_traces(self.fuzzing)
                            self.fuzzing = None
                            self.ioctls[k]['active'] = False
                        
                        else:
                            new_rv = self.ioctls[k]['q'].pop(0)
                            new_rv_u = panda.to_unsigned_guest(new_rv)
                            #print(f"Hook hits on ioctl {request:x} that return to {tb.pc:x} with rv {rv:x} change to {new_rv:x} (unsigned {new_rv_u:x})")
                            panda.arch.set_retval(cpu, new_rv_u, convention="syscall", failure=True if new_rv < 0 else False)
                            panda.enable_callback("post_ioctl")
                            self.ioctls[k]['cur_trace'] = []
                            self.ioctls[k]['cur_rv'] = new_rv

        @panda.cb_start_block_exec(enabled=False)
        def post_ioctl(cpu, tb):
            # Get current program name
            trace = self.ioctls[self.fuzzing]['cur_trace']
            trace.append(tb.pc)

            #disable = panda.in_kernel_code_linux(cpu) # If in kernel we want to bail
            # We want to check if tb.pc is in kernel code, not if the CPU is currently (since we're coming out of kernel)
            disable = tb.pc > 0xffffffff80000000 # x86_64

            if disable:
                # We didn't actually get to fuzz this value, re-add it. Note this could become an infinite loop if this is deterministic...
                print(f"Hit kernel code at {tb.pc:x} with rv={self.ioctls[self.fuzzing]['cur_rv']} with {len(trace)} blocks")# re-adding to queue")
                self.ioctls[self.fuzzing]['q'].append(self.ioctls[self.fuzzing]['cur_rv'])

            if len(trace) >= N_BLOCKS:
                disable = True
                trace_t = tuple(trace)

                observed_traces = self.ioctls[self.fuzzing]['traces']
                rv = self.ioctls[self.fuzzing]['cur_rv']

                if trace_t not in observed_traces:
                    observed_traces[trace_t] = set()

                if rv not in observed_traces[trace_t]:
                    observed_traces[trace_t].add(rv)

            if disable:
                panda.disable_callback("post_ioctl")
                self.panda.revert_async(self.ioctls[self.fuzzing]['snapshot']) # Hits on next main_loop

    def dump_traces(self, k):
        observed_traces = self.ioctls[k]['traces']
        for old_trace, old_rvs in observed_traces.items():
            print(f"Retvals:", ([f"{x:x}" for x in old_rvs]), " map to trace:")
            print(f"\t" + ", ".join([f"{x:08x}" for x in old_trace]))

    # Initial queue has each bit in a 32-bit int set
    @staticmethod
    def make_queue():
        return [0] + [1 << i for i in range(32)] + [x for x in range(-10, 0)] # Try lots of errors too! It's cheap

    @PyPlugin.ppp_export
    def wait(self, user_key):
        # Wait until lock is released. Don't actually hold it though
        # User_key may contain None for either device_name or ioctl_num - if so find first
        # matching key
        keys = [x for x in self.ioctls if (x[0] == user_key[0] or not user_key[0]) and (x[1] == user_key[1] or not user_key[1])]
        if not len(keys):
            raise ValueError(f"Invalid key {user_key}")
        if len(keys) > 1:
            print(f"WARNING: Multiple keys match, using first {user_key} => {keys}")

        k = keys[0]
        while self.ioctls[k]['active']:
            sleep(1)
        return self.ioctls[k]['traces']

    @PyPlugin.ppp_export
    def fuzz(self, device_name=None, ioctl_num=None):
        # Register the specified ioctl for fuzzing
        # Provide user a key for later getting results
        self.fuzz_targets.append((ioctl_num, device_name))
        return (ioctl_num, device_name)