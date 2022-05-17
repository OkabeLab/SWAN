from __future__ import print_function
import subprocess
import configparser
import os
import sys

print("You will delete all swan database, swan logs and cuckoo logs.")
print("If you confirm and continue, please input 'ok'.")
while True:
    val = input("")
    if val == "ok":
        print("Clearing swan database...")
        subprocess.run("sudo rm -rf ../django/media/*", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        print("Cleared!")
        print("Clearing swan logs...")
        subprocess.run("sudo rm -rf ../log/*", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        print("Cleared!")
        print("Clearing cuckoo logs...")
        subprocess.run("cuckoo clear", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        print("Cleared!")
        break
    else:
        print("Canceled!")
        break