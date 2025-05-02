# Author: Breanna Breedlove
# This program takes in the input from "dissector.py" through a named pipe.
# The program then prompts the user to either let the process continue or terminate it.
import subprocess

# open up pipe as input
f = open("mediator_pipe")
print("monitoring for access of file... ctrl-c to stop")
while True:
    # take in input and isolate the process ID
    process = f.readline()
    print(process)
    process = process.split(" ")
    # prompt user and wait for valid answer
    print(str("The process above was accessing a protected_file. Continue the process? Y/N"))
    x = True
    while x:
        answer = input()
        # If the answer is yes, continue the process and respond
        if answer.upper() == "Y":
            sus_str = 'kill' + ' -CONT ' + process[0]
            subprocess.call(sus_str, shell = True)
            print("Process continued.")
            x = False
        # If the answer is no, terminate the process and respond
        elif answer.upper() == "N":
            sus_str = 'kill' + ' -KILL ' + process[0]
            subprocess.call(sus_str, shell = True)
            print("process terminated.")
            x = False
