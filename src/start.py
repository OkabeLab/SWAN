# starting commands need su
from __future__ import print_function
import subprocess
import configparser
import os
import sys
from shlex import quote

class Service:
    def __init__(self, name):
        self.name = name
    
    def start_service(self):
        print(self.name + ' starting...')
        subprocess.run('sudo systemctl restart ' + quote(self.name), shell=True)
        print(self.name + ' started!')

def start_unbound():
    print('unbound starting...')
    subprocess.run("sudo unbound-control start", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    print('unbound started!')

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

# inetsim
inetsim = Service('inetsim')
inetsim.start_service()

# unbound
print ('checking unbound.conf...')
# check config file
if subprocess.run('unbound-checkconf').returncode==1:
    print ('unbound config error!')
    sys.exit()
# unbound = Service('unbound')
# unbound.start_service()
start_unbound()

# cuckoo-rooter
print ('cuckoo rooter starting...')
# run cuckoo webserver on background and output log to file
with open('../log/cuckoo-rooter.log', 'w') as f:
    subprocess.run('cuckoo rooter --sudo &', shell=True, stdout=f, stderr=f)
print ('cuckoo rooter started!')

# cuckoo-web
print ('cuckoo web starting...')
# run cuckoo webserver on background and output log to file
with open('../log/cuckoo-web.log', 'w') as f:
    subprocess.run('cuckoo web runserver &', shell=True, stdout=f, stderr=f)
print ('cuckoo web started!')

# django-server
print("django-server starting...")
with open('../log/django-server.log', 'w') as f:
    subprocess.run('python3 ../django/manage.py runserver &', shell=True, stdout=f, stderr=f)
print("django-server started!")

# set default iprule
if subprocess.run('sudo iptables -t filter -L | grep drop-port', shell=True, stdout=subprocess.PIPE).returncode==1:
    # rule not existed
    subprocess.run('sudo iptables -t filter -A OUTPUT -p tcp --dport 8001 -j DROP -m comment --comment drop-port', shell=True)
if subprocess.run('sudo iptables -t nat -L | grep default-redirect', shell=True, stdout=subprocess.PIPE).returncode==1:
    # rule not existed
    subprocess.run('sudo iptables -t nat -I PREROUTING -s ' + config["virtualbox"]["guest-ip"] + '/32 -i vboxnet0 -p tcp -m tcp ! --dport 53 -m tcp ! --dport 2042 -j DNAT --to-destination '+config["virtualbox"]["ip"]+':8080 -m comment --comment default-redirect', shell=True)

print("successfully started!")