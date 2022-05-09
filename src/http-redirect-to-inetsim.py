"""Redirect HTTP, HTTPS requests to inetsim."""
from mitmproxy import http
import inspect
import configparser
import os


#def clientconnect(layer):
#    layer.server_conn.ip_address = "192.168.56.1"
#    layer.server_conn.address = "192.168.56.1"
#    print(vars(layer.server_conn))

#def websocket_handshake(flow):
#    print("websocket_handshake")

#def websocket_start(flow):
#    print("start")

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

def request(flow):
    # sudo mitmdump --listen-host 192.168.56.1 -p 8080 -s http-redirect-to-inetsim.py -m transparent --ssl-insecure
    # sudo iptables -t nat -I PREROUTING -s 192.168.56.101/32 -i vboxnet0 -p tcp -m tcp ! --dport 53 -m tcp ! --dport 2042 -j REDIRECT --to-ports 8080
    
    host_ip = config["virtualbox"]["ip"]
    # if flow.request.host != "192.168.56.1":
    #     flow.request.host = "192.168.56.1"
    if flow.request.host != host_ip:
        flow.request.host = a
    # if http, redirect to port 80
    if flow.request.scheme=="http":
        flow.request.port = 80
    # if https, redirect to port 443
    elif flow.request.scheme=="https":
        flow.request.port = 443
#        print(vars(flow.server_conn))
#        if flow.server_conn.connection != None:
#            flow.server_conn.ip_address = ("192.168.56.1", 443)
#            flow.server_conn.address = ("192.168.56.1", 443)
#            print(vars(flow.server_conn.connection))            
#            flow.server_conn.connection._socket.close()
#            print(flow.server_conn.connection._socket)

    # if not http or https, redirect to drop port
    else:
        flow.request.port = 8001
