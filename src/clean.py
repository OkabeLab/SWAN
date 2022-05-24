from __future__ import print_function
import subprocess
import sqlite3

print("You will delete all swan database, swan logs and cuckoo logs.")
print("If you confirm and continue, please input 'ok'.")
while True:
    val = input("")
    if val == "ok":
        print("Cleaning swan database...")
        con = sqlite3.connect('../django/db.sqlite3')
        cur = con.cursor()
        # analysisを削除することで，関連するポリシーも削除
        cur.execute('delete from list_analysis')
        con.commit()
        con.close()
        subprocess.run("sudo rm -rf ../django/media/*", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        print("Cleaned!")
        print("Cleaning swan logs...")
        subprocess.run("sudo rm -rf ../log/*", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        print("Cleaned!")
        print("Cleaning cuckoo logs...")
        subprocess.run("cuckoo clean", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        print("Cleaned!")
        break
    else:
        print("Canceled!")
        break