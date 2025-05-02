# Author: Breanna Breedlove
# This file is used to demonstrate the overall program in action
# It accesses the protected file while *should* be detected and promptly paused right after
import time
f = open("/home/bree/honors_project/superSecretFile.txt", "r")
print("Opening Secret File...")
time.sleep(2000)
f.close()
