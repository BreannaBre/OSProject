#!/bin/python3
import time

while True:
    with open("random_file.txt", "w") as f:
        f.write("working")
        time.sleep(0.005)
