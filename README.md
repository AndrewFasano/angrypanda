# AngryPANDA

Example script showing how to switch from a concrete execution of a PANDA guest into symbolic execution using angr.

## `run.py`
* Runs the program `crackme/crackme2` in a PANDA i386 linux guest.
* Copies code and memory into angr on demand and leaves malloc'd buffer as symbolic.
* Finds a solution to solve the crackme, places it in PANDA guest's memory
* Resumes guest execution to execute the success path
* Restarts concrete execution from the beginning and runs crackme with given solution from the start

# Setup
1) Install PANDA from source and install the pandare python package.
2) Install angrypanda requirements with `pip install -r requirements.txt`
