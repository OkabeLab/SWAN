import datetime as dt
import sqlite3
import shutil
import os
import sys
import subprocess
import configparser

def sqlite_put(pktlist, path):
    con = sqlite3.connect('../django/db.sqlite3')
    cur = con.cursor()

    # 現在時刻を取得
    utc_time = dt.datetime.now(dt.timezone.utc)
    # analysisに現在時刻を挿入
    cur.execute('insert into list_analysis (date) values (?)', (utc_time,))
    # 挿入したデータのidを取得
    analysis_id = cur.execute('select id from list_analysis where date = (?)', (utc_time,))
    for row in analysis_id:
        for pkt in pktlist:
            cur.execute('insert into list_packet (analysis_id, timestamp, protocol_id, src_ip, src_port, dst_ip, dst_port, info, dns_query, dns_responce) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        tuple([row[0]] + [pkt["timestamp"], pkt["protocol"], pkt["src"], pkt["sport"], pkt["dst"], pkt["dport"], pkt["info"], pkt["dns_q"], pkt["dns_r"]]))
        # analysis_idに紐付けてパスをデータベースに挿入
        cur.execute("insert into list_uploadfile (file_path, analysis_id) values (?, ?)", tuple([f"{utc_time:%y%m%d%H%M%S}"+".pcap", row[0]]))
        # 上に合わせてファイルをサーバーにコピー
        shutil.copyfile(path, "../django/media/"+f"{utc_time:%y%m%d%H%M%S}"+".pcap")
        
    con.commit()
    con.close()

def sqlite_get_rule(analysis_id):
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

    # unbound_filepath = "/etc/unbound/unbound.conf.d/whitelist.conf"
    unbound_filepath = config["unbound"]["conf.d-path"] + "/whitelist.conf"
    con = sqlite3.connect('../django/db.sqlite3')
    cur = con.cursor()
    # DNS
    # unboundルールを上書き
    with open(unbound_filepath, 'w') as unboundfile:
        # (domain, policy)の形で取得
        for policy in cur.execute("select domain, policy from list_dnspolicy where analysis_id = ?", (analysis_id,)):
            # policyがUBだったならルールを追加
            if policy[1] == "UB":
                unboundfile.write('forward-zone:\n')
                unboundfile.write('    name:"' + policy[0] + '"\n')
                unboundfile.write('    forward-addr:"192.168.255.1"\n')
        # ルールになければシミュレーターへ
        unboundfile.write('forward-zone:\n')
        unboundfile.write('    name:"."\n')
        unboundfile.write('    forward-addr:"192.168.56.1@1053"\n')
    
    # TLS
    all_dst_ip, all_dst_port = "", 0
    # (dst_ip, dst_port, counter, policy)の形で取得
    for policy in cur.execute("select dst_ip, dst_port, counter, policy from list_tlspolicy where analysis_id = ?", (analysis_id,)):
        # counter=0がinvalidでない場合(ALL設定)
        # そのip, portに対してルールをcounterを無視して設定する
        if policy[2] == 0 and policy[3] != "IV":
            all_dst_ip, all_dst_port = policy[0], policy[1]
            # 全て通す場合
            if policy[3] == "PX":
            #    print("ipset n all-px-Pset hash:ip,port counters -exist")
                subprocess.run("sudo ipset n all-px-Pset hash:ip,port counters -exist", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
            #    print("ipset a all-px-Pset "+policy[0]+","+str(policy[1]))
                subprocess.run("sudo ipset a all-px-Pset "+policy[0]+","+str(policy[1]), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
            #    print("iptables -t nat -I PREROUTING -p tcp -m set --match-set all-px dst,dst -j REDIRECT --to-port 8081 -m comment --comment ipset-policy")
                subprocess.run("sudo iptables -t nat -I PREROUTING -p tcp -m set --match-set all-px-Pset dst,dst -j REDIRECT --to-port 8081 -m comment --comment ipset-policy", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        # counter=0がinvalidの場合は特に何もしない
        elif policy[2] == 0:
            pass
        # all設定が有効なので無視するルール
        elif policy[0] == all_dst_ip and policy[1] == all_dst_port:
            pass
        # all設定無効の場合それぞれのcounterのポリシーに従ってルール生成
        else:
            if policy[3] == "PX":
            #    print("ipset n "+policy[0]+","+str(policy[1])+"-"+str(policy[2])+"-Pset hash:ip,port counters")
                subprocess.run("sudo ipset n "+policy[0]+","+str(policy[1])+"-"+str(policy[2])+"-Pset hash:ip,port counters", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
            #    print("ipset a "+policy[0]+","+str(policy[1])+"-"+str(policy[2])+"-Pset "+policy[0]+","+str(policy[1]))
                subprocess.run("sudo ipset a "+policy[0]+","+str(policy[1])+"-"+str(policy[2])+"-Pset "+policy[0]+","+str(policy[1]), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
            #    print("iptables -t nat -I PREROUTING -p tcp -m set --match-set "+policy[0]+","+str(policy[1])+"-"+str(policy[2])+" dst,dst ! --update-counters --packets-eq "+str(policy[2])+" -j REDIRECT --to-port 8081 -m comment --comment ipset-policy")
                subprocess.run("sudo iptables -t nat -I PREROUTING -p tcp -m set --match-set "+policy[0]+","+str(policy[1])+"-"+str(policy[2])+"-Pset dst,dst ! --update-counters --packets-eq "+str(policy[2])+" -j REDIRECT --to-port 8081 -m comment --comment ipset-policy", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
            #    print("iptables -t nat -I PREROUTING -p tcp -m set --match-set "+policy[0]+","+str(policy[1])+"-"+str(policy[2])+" dst,dst --packets-eq 0 -j REDIRECT --to-port 80 -m comment --comment ipset-policy")
                subprocess.run("sudo iptables -t nat -I PREROUTING -p tcp -m set --match-set "+policy[0]+","+str(policy[1])+"-"+str(policy[2])+"-Pset dst,dst --packets-eq 0 -j REDIRECT --to-port 80 -m comment --comment ipset-policy", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)

    # HTTP
    # (dst_ip, dst_port, counter, policy)の形で取得
    for policy in cur.execute("select dst_ip, dst_port, counter, policy from list_httppolicy where analysis_id = ?", (analysis_id,)):
        # counter=0がinvalidでない場合(ALL設定)
        # そのip, portに対してルールをcounterを無視して設定する
        if policy[2] == 0 and policy[3] != "IV":
            all_dst_ip, all_dst_port = policy[0], policy[1]
            # 全て通す場合
            if policy[3] == "PX":
            #    print("ipset n all-px-Pset hash:ip,port counters -exist")
                subprocess.run("sudo ipset n all-px-Pset hash:ip,port counters -exist", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
            #    print("ipset a all-px-Pset "+policy[0]+","+str(policy[1]))
                subprocess.run("sudo ipset a all-px-Pset "+policy[0]+","+str(policy[1]), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
            #    print("iptables -t nat -I PREROUTING -p tcp -m set --match-set all-px dst,dst -j REDIRECT --to-port 8081 -m comment --comment ipset-policy")
                subprocess.run("sudo iptables -t nat -I PREROUTING -p tcp -m set --match-set all-px-Pset dst,dst -j REDIRECT --to-port 8081 -m comment --comment ipset-policy", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        # counter=0がinvalidの場合は特に何もしない
        elif policy[2] == 0:
            pass
        # all設定が有効なので無視するルール
        elif policy[0] == all_dst_ip and policy[1] == all_dst_port:
            pass
        # all設定無効の場合それぞれのcounterのポリシーに従ってルール生成
        else:
            if policy[3] == "PX":
                # print("ipset n "+policy[0]+","+str(policy[1])+"-"+str(policy[2])+"-Pset hash:ip,port counters")
                subprocess.run("sudo ipset n "+policy[0]+","+str(policy[1])+"-"+str(policy[2])+"-Pset hash:ip,port counters", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
                # print("ipset a "+policy[0]+","+str(policy[1])+"-"+str(policy[2])+"-Pset "+policy[0]+","+str(policy[1]))
                subprocess.run("sudo ipset a "+policy[0]+","+str(policy[1])+"-"+str(policy[2])+"-Pset "+policy[0]+","+str(policy[1]), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
                # print("iptables -t nat -I PREROUTING -p tcp -m set --match-set "+policy[0]+","+str(policy[1])+"-"+str(policy[2])+" dst,dst ! --update-counters --packets-eq "+str(policy[2])+" -j REDIRECT --to-port 8081 -m comment --comment ipset-policy")
                subprocess.run("sudo iptables -t nat -I PREROUTING -p tcp -m set --match-set "+policy[0]+","+str(policy[1])+"-"+str(policy[2])+"-Pset dst,dst ! --update-counters --packets-eq "+str(policy[2])+" -j REDIRECT --to-port 8081 -m comment --comment ipset-policy", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
                # print("iptables -t nat -I PREROUTING -p tcp -m set --match-set "+policy[0]+","+str(policy[1])+"-"+str(policy[2])+" dst,dst --packets-eq 0 -j REDIRECT --to-port 80 -m comment --comment ipset-policy")
                subprocess.run("sudo iptables -t nat -I PREROUTING -p tcp -m set --match-set "+policy[0]+","+str(policy[1])+"-"+str(policy[2])+"-Pset dst,dst --packets-eq 0 -j REDIRECT --to-port 80 -m comment --comment ipset-policy", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    
# sudoでの実行を強制する
if os.geteuid() == 0:
    print("We're root!")
    sqlite_get_rule(sys.argv[1])
else:
    print("We're not root.")
    subprocess.call(['sudo', 'python3', *sys.argv])
    sys.exit()

