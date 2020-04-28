#!/usr/bin/env python
#coding: utf-8


import hashlib
from base64 import b64encode, b64decode
import sys
import os
from platform import python_version

Begin = "clear"
if sys.version_info[0] < 3:
    version = python_version()
    print("\n\033[32m You are using python in the version\033[1;m \033[1m\033[31m%s\033[1;m \033[32mand it is lower than python3 onwards.\033[1;m" %(versao))
    print("\033[32m Please run program with a higher version than python2\033[1;m\n")
    exit(1)

def Applicatoin():
    os.system(Begin)
    print("""\033[31m

	 ▄  █ ██      ▄▄▄▄▄    ▄  █     ▄█▄    ████▄ ██▄   ▄███▄   
	█   █ █ █    █     ▀▄ █   █     █▀ ▀▄  █   █ █  █  █▀   ▀  
	██▀▀█ █▄▄█ ▄  ▀▀▀▀▄   ██▀▀█     █   ▀  █   █ █   █ ██▄▄    
	█   █ █  █  ▀▄▄▄▄▀    █   █     █▄  ▄▀ ▀████ █  █  █▄   ▄▀ 
	   █     █               █      ▀███▀        ███▀  ▀███▀   
	  ▀     █               ▀                               
	       ▀                             \033[1mBy: Souradeepta\033[1;m

""")