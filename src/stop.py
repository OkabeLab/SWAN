import subprocess

class Service:
    def __init__(self, name):
        self.name = name
    
    def stop_service(self):
        print(self.name + ' stopping...')
        subprocess.call('sudo systemctl stop ' + self.name, shell=True)
        print(self.name + ' stopped!')

    def kill_service(self):
        print(self.name + ' stopping...')
        subprocess.call('ps aux | grep -v grep | grep "'+self.name+'" | awk \'{print "sudo kill -9 " $2}\' | sh', shell=True)
        print(self.name + ' stopped!')
    

def reset_unbound():
    unbound_filepath = "/etc/unbound/unbound.conf.d/whitelist.conf"
    default_filepath = "conf/unbound_default.conf"
    subprocess.run("sudo cp -f " + default_filepath + " " + unbound_filepath, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)

def stop_unbound():
    print('unbound stopping...')
    subprocess.run("sudo unbound-control stop", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    print('unbound stopped!')

def reset_ipset_policy():
    # ipset destroy -set-for-policy
    subprocess.run('sudo ipset l -name | grep "-set-for-policy" | awk \'{print "sudo ipset x " $1}\' | sh', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)

def reset_iptables_policy():
    # iptables-save remove ipset-policy by comment and iptables-restore
    subprocess.run('sudo iptables-save | grep -v ipset-policy | sudo iptables-restore', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)


# inetsim
inetsim = Service('inetsim')
inetsim.stop_service()

# unbound
stop_unbound()
reset_unbound()

# cuckoo-rooter
cuckoo = Service('cuckoo rooter')
cuckoo.kill_service()

# cuckoo-web
cuckoo = Service('cuckoo web')
cuckoo.kill_service()

# django-server
django = Service("django")
django.kill_service()

# iptables, ipset
# reset iptables
print('reset iptables...')
reset_iptables_policy()
print('finished!')
# reset ipset
print('reset ipset...')
reset_ipset_policy()
print('finished!')


print("successfully stopped!")