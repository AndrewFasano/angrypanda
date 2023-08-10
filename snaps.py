from pandare import Panda
from ioctlfuzz import IoctlFuzz

panda = Panda(generic="x86_64")

@panda.queue_blocking
def driver():
    panda.revert_sync("root")
    panda.copy_to_guest("crackme")

    # Load after CD interactions just to simplify
    panda.pyplugins.load(IoctlFuzz)

    target = panda.pyplugins.ppp.IoctlFuzz.fuzz(None, 0x123456) # any device, this ioctl

    print(panda.run_serial_cmd("crackme/ioctl_crackme", timeout=9999))

    # We expect to encounter an ioctl we'll fuzz - wait for it.
    print("WAIT FOR RESULT")
    fuzz_result = panda.pyplugins.ppp.IoctlFuzz.wait(target)
    print("GOT RESULT:", fuzz_result)

    panda.end_analysis()
    

panda.run()