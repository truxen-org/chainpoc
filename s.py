#!/usr/bin/python3
import shutil 
import os
from subprocess import call

fo = ".chainpoc"
ft = ".tmp" 
p0 = "~/test/cp"
p1 = "~/test/cp1"
p2 = "~/test/cp2"

def reset_env(p):
    p = os.path.expanduser(p)
    print("handling ", p)
    pfo = os.path.join(p, fo);
    pft = os.path.join(p, ft);
    #clean base folder
    if os.path.exists(pft):
        shutil.rmtree(pft)
    if os.path.exists(pfo):
        shutil.rmtree(pfo) 
    print("done reset")

# shutdown processes
call('pkill -f chainpoc', shell=True);
# build
call('go build', shell=True);

# if os.path.exists(fo):
#         shutil.rmtree(fo)
reset_env(p0);
# reset_env(p2);
