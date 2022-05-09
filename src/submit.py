# submit file and analysis
from __future__ import print_function
import subprocess
import configparser
import os
import json
from shlex import quote
import datetime
import collections
import scapy_function as sf
import sys

class Service:
    def __init__(self, name):
        self.name = name
    
    def kill_service(self):
        print(self.name + ' stopping...')
        subprocess.call('ps aux | grep -v grep | grep "'+self.name+'" | awk \'{print "sudo kill -9 " $2}\' | sh', shell=True)
        print(self.name + ' stopped!')

def start_mitmdump(filename, port):
    print ('mitmdump starting...')
    # run mitmdump on background and output log to file
    # save traffic with mode append
    with open('../log/mitm-std.log', 'w') as fm:
        subprocess.run('mitmdump -w +'+quote(filename)+' --listen-host '+quote(config.get('virtualbox', 'ip'))+' -p '+quote(port)+' -m transparent &', shell=True, stdout=fm, stderr=fm)
    print ('mitmdump started!')

def start_tcpdump(filename):
    print('tcpdump starting...')
    with open('../log/tcpdump.log', 'w') as ft:
        subprocess.run('tcpdump \(tcp or udp\) -s 0 -w '+quote(filename)+' -i '+quote(config.get('tcpdump', 'interface'))+' &', shell=True, stdout=ft, stderr=ft)
    print('tcpdump started!')

# wiresharkのsshdumpをkillしないように分離
def stop_tcpdump():
        print('tcpdump stopping...')
        subprocess.call('ps aux | grep -v grep | grep tcpdump.out | awk \'{print "sudo kill -9 " $2}\' | sh', shell=True)
        print('tcpdump stopped!')


def reset_ipset_policy():
    # ipset destroy -Pset
    subprocess.run('sudo ipset l -name | grep "-Pset" | awk \'{print "sudo ipset x " $1}\' | sh', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)

def reset_iptables_policy():
    # iptables-save remove ipset-policy by comment and iptables-restore
    subprocess.run('sudo iptables-save | grep -v ipset-policy | sudo iptables-restore', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)


# make directory
os.makedirs('../conf', exist_ok=True)
os.makedirs('../log', exist_ok=True)

# load config file
config = configparser.ConfigParser()
# config file exist
if os.path.isfile('../conf/swan.conf'):
    with open('../conf/swan.conf', 'r') as configfile:
        config.read_file(configfile)
    print('loading config completed!')
# config file not exist
else:
    print('config file is not existed!')


# prepare for analysis
start_proc = subprocess.Popen('python3 start.py', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
# start_proc = subprocess.run('python3 start.py', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
# print(start_proc.stdout.decode("utf-8"))
# realtime reload
for line in iter(start_proc.stdout.readline, b''):
    l = line.rstrip().decode("utf-8")
    print(l)
while True:
    # cuckoo submit
    print('please input filename in malware folder for analyse')
    # get path to analysis-file
    malware_name = input()
    analysis_path = "../malware/" + malware_name
    if os.path.isfile(analysis_path):
        print("Enter 'ok' or 'AnalysisID' if you want to apply the past policy.")
        while True:
            val = input("")
            if val == "ok":
                break
            # IDが入力された場合
            elif val.isdecimal:
                proc = subprocess.run('sudo python3 get_policy.py '+val, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
                print(proc.stdout.decode("utf-8"))
                # unbound reload
                subprocess.run('sudo unbound-control reload', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
                break
        break
    else:
        print('not such file "'+ malware_name + '" in malware folder')

# 以下繰り返し
while True:
    dt_now = datetime.datetime.now()
    print(dt_now)
    dt = dt_now.strftime('%y%m%d%H%M')

    # make directory
    os.makedirs('../log/' + malware_name + '/' + dt, exist_ok=True)

    # mitmdump
    mitm_inet_path = '../log/' + malware_name + '/' + dt + '/mitmdump-to-inetsim.log'
    mitm_inet_out_path = '../log/' + malware_name + '/' + dt + '/mitmdump-to-inetsim.out'
    mitm_out_path = '../log/' + malware_name + '/' + dt + '/mitmdump-out.log'
    mitm_out_out_path = '../log/' + malware_name + '/' + dt + '/mitmdump-out.out'
    with open(mitm_inet_path, 'w') as f:
        subprocess.run('mitmdump -w '+mitm_inet_out_path+' --listen-host '+config["virtualbox"]["ip"]+' -p 8080 -s http-redirect-to-inetsim.py -m transparent --ssl-insecure --set upstream_cert=false &', shell=True, stdout=f, stderr=f)
    with open(mitm_out_path, 'w') as f:
        subprocess.run('mitmdump -w '+mitm_out_out_path+' --listen-host '+config["virtualbox"]["ip"]+' -p 8081 -m transparent --ssl-insecure --set upstream_cert=false &', shell=True, stdout=f, stderr=f)
    # start_mitmdump('log/' + malware_name + '/' + dt + '/mitmdump-out.log', '8081')

    # tcpdump
    dump_path = '../log/' + malware_name + '/' + dt + '/tcpdump.out'
    start_tcpdump(dump_path)

    # set timeout and submit
    proc = subprocess.run('cuckoo submit -o human=0 --timeout '+config["cuckoo"]["timeout"]+' '+quote(analysis_path), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    print(proc.stdout)
    # get task ID from stdout
    test_id = proc.stdout.split()

    # cuckoo
    print ('cuckoo starting...')
    cuckoo_proc = subprocess.Popen('cuckoo', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    # realtime reload
    for line in iter(cuckoo_proc.stdout.readline, ''):
        l = line.rstrip()
        print(l)
        # successfully finish analysis
        # remove color code
        if l.replace('\x1b[0m','').endswith(test_id[-1] + ': analysis procedure completed'):
            # kill cuckoo
            cuckoo_proc.terminate()

            # cuckooのログからpcapファイルを引っ張ってくる
            cuckoo_pcap_path = config["cuckoo"]["cwd-path"]+"/storage/analyses/"+test_id[-1][1:]+"/dump.pcap"
            print(cuckoo_pcap_path)
            if cuckoo_pcap_path[0] == "~":
                cuckoo_pcap_path = os.environ['HOME'] + cuckoo_pcap_path[1:]
            print(cuckoo_pcap_path)

            # kill mitmdump
            mitmdump = Service('mitmdump')
            mitmdump.kill_service()

            # kill tcpdump
            # tcpdump = Service('tcpdump')
            # tcpdump.kill_service()
            stop_tcpdump()

            # reset iptables
            reset_iptables_policy()
            # reset ipset
            reset_ipset_policy()
            # scapyで情報抽出
            print("Loading captured packets")
            # summary = sf.packet_summary(dump_path)
            summary = sf.packet_summary(cuckoo_pcap_path)
            # djangoのデータベースに提出, 解析IDも取得しておく
            print("Now submitting...")
            # analysis_id = str(sf.sqlite_put(summary, dump_path))
            analysis_id = str(sf.sqlite_put(summary, cuckoo_pcap_path, mitm_inet_path))
            print("Submitted!")
            # # 解析を続けるか問う
            # while True:
            #     choice = input("Continue analysis? [y/N]: ").lower()
            #     if choice in ["y", "ye", "yes"]:
            #         # 続ける場合はポリシーを設定してもらう
            #         print("Access to 'http://127.0.0.1:9000/list', AnalysisID: "+analysis_id+" and set policy")
            #         break        
            #     elif choice in ["n", "no"]:
            #         proc = subprocess.run('python3 stop.py', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
            #         print(proc.stdout.decode("utf-8"))
            #         print("Analysis finished!")
            #         sys.exit(0)
            print("Access to 'http://127.0.0.1:9000/list', AnalysisID: "+analysis_id+" and set policy")
            print("Enter 'ok' when you done. 'stop' to stop analysis.")
            print("'AnalysisID' if you want to apply the past policy.")
            while True:
                val = input("")
                if val == "ok":
                    break
                elif val =="stop":
                    proc = subprocess.run('python3 stop.py', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
                    print(proc.stdout.decode("utf-8"))
                    dt_now = datetime.datetime.now()
                    print(dt_now)
                    print("Analysis finished!")
                    sys.exit(0)
                # IDが入力された場合
                elif val.isdecimal:
                    # 指定IDが現在の値より大きい場合
                    if int(analysis_id) <= int(val):
                        print('AnalysisID is too big!')
                    # 過去のポリシーを指定した場合はanalysis_idを書き換え
                    else:
                        analysis_id = val
                        break
            proc = subprocess.run('sudo python3 get_policy.py '+analysis_id, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
            print(proc.stdout.decode("utf-8"))
            # unbound reload
            subprocess.run('sudo unbound-control reload', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        # cuckoo is already runnning
        elif 'Cuckoo is already running' in l:
            # remove color code
            # kill process
            killp = subprocess.run('kill -9 '+l.split()[-1].replace('\x1b[0m\x1b[0m','') , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            # kill mitmdump
            mitmdump = Service('mitmdump')
            mitmdump.kill_service()
            # kill tcpdump
            tcpdump = Service('tcpdump')
            tcpdump.kill_service()
            print('process killed! please retry')
            cuckoo_proc.terminate()
