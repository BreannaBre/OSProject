#!/bin/python3
# Author: Breanna Breedlove
# This program is used to filter "opensnoop.py"'s output
# If a 'protected' file is being reached, this will suspend the program and move the process's info to the confirmer
# via a 'mediator pipe'

import time
import subprocess

# TODO: fix absulte path stuff
# subp = subprocess.Popen('realpath superSecretFile.txt', stdout=subprocess.PIPE, shell=True)
# secretpath = subp.stdout.read()

# list is made to add multiple files to protect, but did not implement a way to add them without doing it manually :(
secretpath = "honors_project/superSecretFile.txt"
protected_files = [secretpath]

# begin taking in input
while True:
    processline = input()
    for f in protected_files:
        # if file is accessed, pause the program
        if processline.find(f) != -1:
            split_str = processline.split(' ')

            subprocess_str = 'kill' + ' -TSTP ' + str(split_str[0])
            subprocess.call(subprocess_str, shell = True)
            # output the process's info for the confirmer to take in'
            print(processline)
