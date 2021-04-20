import time
import subprocess
import random
import os

step = 1000000
times = 20

client = "ClientCP1"
server = "ServerCP1"

with open("time_"+client+".csv", "w") as outfile:
    for size in range(step, step*(times+1), step):
        print(size)
        with open("client_res/test.bin", "wb") as f:
            f.write(random.randbytes(size))
        start = time.time()
        subprocess.call(["java", client, "test.bin"])
        runtime = time.time() - start
        outfile.write(f"{size}\t{runtime}\n")
