# AngryPANDA

Example script showing how to switch from a concrete execution of a PANDA guest into symbolic execution using angr.

## `run.py`
* Runs the program `crackme/crackme2` in a PANDA i386 linux guest.
* Copies code and memory into angr on demand and leaves malloc'd buffer as symbolic.
* Finds a solution to solve the crackme, places it in PANDA guest's memory
* Resumes guest execution to execute the success path
* Restarts concrete execution from the beginning and runs crackme with given solution from the start

# Setup

Install angr using github.com/angr/angr-dev
Download panda (with python interface) from github.com/panda-re/panda

Run `workon angr` then cd to panda/panda/pypanda/ and run `python setup.py install`.
Now your virtual environment (named angr) should have the latest version of angr and panda with it's python interface.

Note this assumes python is python3, if it isn't, update the commands accordingly.
