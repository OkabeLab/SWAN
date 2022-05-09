from scapy.all import *
from scapy.layers.http import *
from scapy.layers.inet6 import IPv6
from scapy.layers.tls.all import *
from scapy.layers.inet import *
from scapy.layers.dns import *
from scapy.packet import *
import datetime as dt
import sqlite3
import shutil

def packet_summary(filepath):
    load_packets = rdpcap(filepath)
    # DNS rcode
    dns_rcode=["NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN", "XRRSET", "NOTAUTH", "NOTZONE"]
    # HTTP methods
    methods=['GET','POST','HEAD','PUT','DELETE','CONNECT','OPTIONS','TRACE']
    # TLS version対応表
    TLS_VERSIONS = {
        # SSL
        2: "SSL 2.0",
        768: "SSL 3.0",
        # TLS:
        769: "TLS 1.0",
        770: "TLS 1.1",
        771: "TLS 1.2",
        772: "TLS 1.3",
        # DTLS
        256: "PROTOCOL DTLS 1.0 OPENSSL PRE 0.9.8f",
        32528: "TLS 1.3 DRAFT 16",
        32530: "TLS 1.3 DRAFT 18",
        65279: "DTLS 1.0",
        65277: "DTLS 1.1",
    }
    # return用リスト
    packets = []
    for l_pkt in load_packets:
        # DNS TCP
        if DNS in l_pkt and TCP in l_pkt and (l_pkt[TCP].sport==53 or l_pkt[TCP].dport==53):
            # 辞書形式で必要なデータを抽出
            packet = {}
            packet["dns_q"] = ""
            packet["dns_r"] = ""
            packet["timestamp"] = dt.datetime.fromtimestamp(float(l_pkt.time), dt.timezone.utc)
            packet["protocol"] = 1
            # IPv4
            if IP in l_pkt:
                packet["src"] = l_pkt[IP].src
                packet["dst"] = l_pkt[IP].dst
            # IPv6
            else:
                packet["src"] = l_pkt[IPv6].src
                packet["dst"] = l_pkt[IPv6].dst
            # TCP
            packet["sport"] = l_pkt[TCP].sport
            packet["dport"] = l_pkt[TCP].dport
            # info用の変数
            info = ""
            # クエリ
            if l_pkt[DNS].qr==0:
                info += "Query: "
                info += l_pkt[DNS][DNSQR].qname.decode("utf-8")
                packet["dns_q"] = l_pkt[DNS][DNSQR].qname.decode("utf-8")
            # レスポンス, エラーなし
            elif l_pkt[DNS].qr==1 and l_pkt[DNS].rcode==0:
                info += "Response: "
                # no answer
                if l_pkt[DNS].an == None:
                    info += l_pkt[DNS].qd.qname.decode("utf-8")
                    info += "-> No answer"
                    packet["dns_q"] = l_pkt[DNS].qd.qname.decode("utf-8")
                else:
                    # クエリ
                    info += l_pkt[DNS].an[0].rrname.decode("utf-8")
                    packet["dns_q"] = l_pkt[DNS].an[0].rrname.decode("utf-8")
                    for i in range(l_pkt[DNS].ancount):
                        info += " -> "
                        # レスポンス(IPアドレス)
                        if type(l_pkt[DNS].an[i].rdata)==str:
                            info += l_pkt[DNS].an[i].rdata
                            packet["dns_r"] = l_pkt[DNS].an[i].rdata
                        # レスポンス(ドメイン)
                        else:
                            info += l_pkt[DNS].an[i].rdata.decode("utf-8")
            # エラー時
            else:
                info += dns_rcode[l_pkt[DNS].rcode]
            packet["info"] = info
            packets.append(packet)
        # DNS, UDP
        if DNS in l_pkt and UDP in l_pkt and (l_pkt[UDP].sport==53 or l_pkt[UDP].dport==53):
            # l_pkt.show()
            # 辞書形式で必要なデータを抽出
            packet = {}
            packet["dns_q"] = ""
            packet["dns_r"] = ""
            packet["timestamp"] = dt.datetime.fromtimestamp(float(l_pkt.time), dt.timezone.utc)
            packet["protocol"] = 1
            # IPv4
            if IP in l_pkt:
                packet["src"] = l_pkt[IP].src
                packet["dst"] = l_pkt[IP].dst
            # IPv6
            else:
                packet["src"] = l_pkt[IPv6].src
                packet["dst"] = l_pkt[IPv6].dst
            # UDP
            packet["sport"] = l_pkt[UDP].sport
            packet["dport"] = l_pkt[UDP].dport
            # info用の変数
            info = ""
            # クエリ
            if l_pkt[DNS].qr==0:
                info += "Query: "
                info += l_pkt[DNS][DNSQR].qname.decode("utf-8")
                packet["dns_q"] = l_pkt[DNS][DNSQR].qname.decode("utf-8")
            # レスポンス, エラーなし
            elif l_pkt[DNS].qr==1 and l_pkt[DNS].rcode==0:
                info += "Response: "
                # no answer
                if l_pkt[DNS].an == None:
                    # print("answer is none")
                    # print(l_pkt[DNS].qd.qname.decode("utf-8"))
                    info += l_pkt[DNS].qd.qname.decode("utf-8")
                    info += "-> No answer"
                    packet["dns_q"] = l_pkt[DNS].qd.qname.decode("utf-8")
                # MXレコード
                elif l_pkt[DNS].an.type == 15:
                    # クエリ
                    info += l_pkt[DNS].an[0].rrname.decode("utf-8")
                    packet["dns_q"] = l_pkt[DNS].an[0].rrname.decode("utf-8")
                    for i in range(l_pkt[DNS].ancount):
                        info += " -> "
                        # レスポンス(IPアドレス)
                        if type(l_pkt[DNS].an[i].exchange)==str:
                            info += l_pkt[DNS].an[i].exchange
                            packet["dns_r"] = l_pkt[DNS].an[i].exchange
                        # レスポンス(ドメイン)
                        else:
                            info += l_pkt[DNS].an[i].exchange.decode("utf-8")
                else:
                    # クエリ
                    info += l_pkt[DNS].an[0].rrname.decode("utf-8")
                    packet["dns_q"] = l_pkt[DNS].an[0].rrname.decode("utf-8")
                    for i in range(l_pkt[DNS].ancount):
                        info += " -> "
                        # レスポンス(IPアドレス)
                        if type(l_pkt[DNS].an[i].rdata)==str:
                            info += l_pkt[DNS].an[i].rdata
                            packet["dns_r"] = l_pkt[DNS].an[i].rdata
                        # レスポンス(ドメイン)
                        else:
                            info += l_pkt[DNS].an[i].rdata.decode("utf-8")
            # エラー時
            else:
                info += dns_rcode[l_pkt[DNS].rcode]
            packet["info"] = info
            packets.append(packet)
        # HTTP
        # HTTPが認識された場合
        elif HTTPRequest in l_pkt:
            # 辞書形式で必要なデータを抽出
            packet = {}
            packet["dns_q"] = ""
            packet["dns_r"] = ""
            packet["timestamp"] = dt.datetime.fromtimestamp(float(l_pkt.time), dt.timezone.utc)
            packet["protocol"] = 2
            packet["src"] = l_pkt[IP].src
            packet["sport"] = l_pkt[TCP].sport
            packet["dst"] = l_pkt[IP].dst
            packet["dport"] = l_pkt[TCP].dport
            packet["info"] = l_pkt[HTTPRequest].Method.decode("utf-8", "ignore") +" "+ l_pkt[HTTPRequest].Path.decode("utf-8", "ignore") +" "+ l_pkt[HTTPRequest].Http_Version.decode("utf-8", "ignore")
            packets.append(packet)
        # TCPでペイロードあり
        elif TCP in l_pkt and Raw in l_pkt:
            for method in methods:
                # ペイロードがmethodsのどれかで始まっている(HTTP)
                if(l_pkt[Raw].load.startswith(method.encode("utf-8"))):
                    # 辞書形式で必要なデータを抽出
                    packet = {}
                    packet["dns_q"] = ""
                    packet["dns_r"] = ""
                    packet["timestamp"] = dt.datetime.fromtimestamp(float(l_pkt.time), dt.timezone.utc)
                    packet["protocol"] = 2
                    packet["src"] = l_pkt[IP].src
                    packet["sport"] = l_pkt[TCP].sport
                    packet["dst"] = l_pkt[IP].dst
                    packet["dport"] = l_pkt[TCP].dport
                    packet["info"] = l_pkt[Raw].load.decode("utf-8", "ignore")
                    packets.append(packet)
        # TLS
        elif TLS in l_pkt:
            # type: handshake, client hello
            if l_pkt[TLS].type==22 and "TLS Handshake - Client Hello" in l_pkt[TLS]:
                # 辞書形式で必要なデータを抽出
                packet = {}
                packet["dns_q"] = ""
                packet["dns_r"] = ""
                packet["timestamp"] = dt.datetime.fromtimestamp(float(l_pkt.time), dt.timezone.utc)
                packet["protocol"] = 3
                packet["src"] = l_pkt[IP].src
                packet["sport"] = l_pkt[TCP].sport
                packet["dst"] = l_pkt[IP].dst
                packet["dport"] = l_pkt[TCP].dport
                info = ""
                if ServerName in l_pkt[TLS]:
                    info += "Server Name: "
                    info += l_pkt[TLS][ServerName].servername.decode("utf-8")
                    info += ", "
                info += "Version: "
                info += TLS_VERSIONS[l_pkt[TLS].version]
                packet["info"] = info
                packets.append(packet)
    return packets

def sqlite_put(pktlist, pcappath, mitmpath):
    con = sqlite3.connect('../django/db.sqlite3')
    cur = con.cursor()

    # 現在時刻を取得
    utc_time = dt.datetime.now(dt.timezone.utc)
    # analysisに現在時刻を挿入
    cur.execute('insert into list_analysis (date) values (?)', (utc_time,))
    # 挿入したデータのidを取得
    analysis_id = cur.execute('select id from list_analysis where date = (?)', (utc_time,))
    for row in analysis_id:
        id = row[0]
        for pkt in pktlist:
            cur.execute('insert into list_packet (analysis_id, timestamp, protocol_id, src_ip, src_port, dst_ip, dst_port, info, dns_query, dns_responce) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        tuple([row[0]] + [pkt["timestamp"], pkt["protocol"], pkt["src"], pkt["sport"], pkt["dst"], pkt["dport"], pkt["info"], pkt["dns_q"], pkt["dns_r"]]))
        # analysis_idに紐付けてパスをデータベースに挿入
        cur.execute("insert into list_uploadfile (file_path, analysis_id) values (?, ?)", tuple([f"{utc_time:%y%m%d%H%M%S}", row[0]]))
        # 上に合わせてファイルをサーバーにコピー
        shutil.copyfile(pcappath, "../django/media/"+f"{utc_time:%y%m%d%H%M%S}"+".pcap")
        shutil.copyfile(mitmpath, "../django/media/"+f"{utc_time:%y%m%d%H%M%S}"+".log")
    con.commit()
    con.close()
    return id