# SWAN(Sandbox with traffic Whitelisting for ANalyzing malware)

## SWANとは
Cuckooを用いたマルウェア解析を支援するツールです．
DNS, HTTP, HTTPS通信を制御して，望まない通信が外部に接続することを防ぎながら解析を行うことができます．
具体的には，一度全ての通信をインターネットシミュレータへと接続し，確認された通信のうち外部へ接続したい通信を選ぶことで，
その通信だけを外部へ接続して解析を行います．

### 導入
Ubuntu 20.04.4上にCLIでセットアップする手順を示します．
#### Cuckooのセットアップ
```bash
sudo apt install python python3-pip python-dev libffi-dev libssl-dev
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
sudo python2 get-pip.py
sudo apt install python3-virtualenv python-setuptools
sudo apt install libjpeg-dev zlib1g-dev swig
sudo apt install mongodb
sudo apt autoremove
echo deb [arch=amd64] http://download.virtualbox.org/virtualbox/debian focal contrib | sudo tee -a /etc/apt/sources.list.d/virtualbox.list
wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
sudo apt install virtualbox-6.1(新しいバージョンはVB5.2はサポートしていない)
sudo apt install tcpdump apparmor-utils
sudo aa-disable /usr/sbin/tcpdump
sudo groupadd pcap
sudo usermod -a -G pcap swan
sudo chgrp pcap /usr/sbin/tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
```

#### VirtualBoxのセットアップ
Windowsマシンを立てる
```bash
vboxmanage createvm –name windows-cuckoo
vboxmanage registervm /home/swan/”VirtualBox VMs”/windows-cuckoo/windows-cuckoo.vbox
vboxmanage hostonlyif create
vboxmanage modifyvm windows-cuckoo --ostype windows10_64 --memory 4096 --acpi on --ioapic on --cpus 2 --hwvirtex on --nestedpaging on --largepages on --clipboard bidirectional --nic1 hostonly --hostonlyadapter1 vboxnet0 –vrde on
vboxmanage storagectl windows-cuckoo --name SATA --add sata
vboxmanage createhd --size 16384 --variant Fixed --filename "/home/swan/VirtualBox VMs/windows-cuckoo/windows-cuckoo.vdi"
vboxmanage storageattach windows-cuckoo --storagectl SATA --port 0 --type dvddrive --medium "/home/swan/iso/'Windowsのisoファイル'"
vboxmanage storageattach windows-cuckoo --storagectl SATA --port 1 --type hdd --medium "/home/swan/VirtualBox VMs/windows-cuckoo/windows-cuckoo.vdi"
vboxmanage storageattach windows-cuckoo --storagectl SATA --port 2 --type dvddrive --medium ~/iso/VBoxGuestAdditions_6.1.10.iso
sudo vboxmanage extpack install --replace Oracle_VM_VirtualBox_Extension_Pack-6.1.34.vbox-extpack
```

#### Cuckoo 設定
```bash
sudo adduser cuckoo
sudo usermod -a -G vboxusers cuckoo
sudo pip2 install -U pip setuptools
sudo pip2 install -U cuckoo
sudo iptables -t nat -A POSTROUTING -o eth0 -s 192.168.56.0/24 -j MASQUERADE
sudo iptables -P FORWARD DROP
sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -s 192.168.56.0/24 -j ACCEPT
sudo iptables -A FORWARD -s 192.168.56.0/24 -d 192.168.56.0/24 -j ACCEPT
sudo iptables -A FORWARD -j LOG
echo 1 | sudo tee -a /proc/sys/net/ipv4/ip_forward
sudo sysctl -w net.ipv4.ip_forward=1
sudo apt install iptables-persistent
```

#### SWAN　インストール
```bash
sudo apt install ipset
mitmdumpのバイナリをダウンロードして解凍し，/usr/binに置く
sudo apt install unbound
/etc/unbound/unbound.conf.d/server.confを作成
# to save cache for 1 day
server:
	cache-min-ttl: 86400
	interface: 192.168.56.1@53(virtualboxのip)
	access-control: 192.168.56.0/24 allow
/etc/unbound/unbound.conf.d/whitelist.confを作成
forward-zone:
    name:"."
    forward-addr:"192.168.a.b"(名前解決できるnameserver)
/etc/unbound/unbound.conf.d/remote.confを作成
# enable remote control
remote-control:
	control-enable: yes
unbound-checkconfコマンドで設定に問題がないことを確認する
sudo apt install inetsim
/etc/inetsim/inetsim.conf
start_service dns, http, https以外をコメントアウト
    service_bind_address 192.168.56.1
    dns_bind_port 1053
    dns_default_ip 192.168.56.1
pip3 install django
pip3 install scapy
sudo apt install git
git clone https://…(このリポジトリ)
```

#### Windows上での設定
```bash
ファイアウォールを切る
ping 192.168.56.1(Windows側から)
ping 192.168.56.101(ホスト側から)が通るのを確認する
pythonをインストール(shareフォルダを設定し，インストーラを入れる)
ネットワークと共有センター/イーサネット/プロパティ/IPv4からIPを固定する
IP: 192.168.56.101
mask: 255.255.255.0
gateway: 192.168.56.1
DNS server: 192.168.56.1
--—(host)---
sudo unbound-control startでunboundを起動
windows側からnslookupできることを確認する
SWAN/src/start.pyを実行する
python3 start.py
sudo iptables -t nat -Lで192.168.56.101から192.168.56.1:8080へのリダイレクトルールが追加されていることを確認する
mitmdump --listen-host 192.168.56.1 -p 8080 -s http-redirect-to-inetsim.py -m transparent --ssl-insecure --set upstream_cert=false
--—(host)---
ブラウザでhttp://google.comなどにアクセスしてinetsimからの応答があることを確認する
https://docs.mitmproxy.org/stable/concepts-certificates/に従ってmitm.itにアクセスする
信頼されたルート証明機関としてmitmproxyの証明書を登録する
mitmdump --listen-host 192.168.56.1 -p 8080 -s http-redirect-to-inetsim.py -m transparent --ssl-insecure --set upstream_cert=false
この状態でwindows側からhttp, https接続をしようとするとinetsimから応答が返る
mitmdump --listen-host 192.168.56.1 -p 8080 -m transparent --ssl-insecure --set upstream_cert=false
これで全ての通信を通すことができる
python -m pip install Pillowだとpip側のサーバで証明書が検証されてmitmproxy経由ではうまくいかない
https://pypi.org/project/Pillow/6.2.2/#filesからpython2, windows64bit用のwhlファイルをダウンロードする
>python -m pip install Pillow-6.2.2-cp27-cp27m-win_amd64.whl
office suite, adobeのインストーラをローカルに落としてファイル共有でwindowsへ
windows以外の場合は全ての通信を通す状態でそれぞれのインストーラのリンクをVM上で確認できる(もしくはそのままVM上で落としても良い)
https://helpx.adobe.com/jp/acrobat/kb/cq05201026.html, Dに従ってadobeのアップデート設定を切っておく
word, excelの設定でマクロを有効にしておく
UACを無効にする
agent.pyを設置，管理者で実行してスナップショットを作成
隠しファイル，拡張子表示にしてuser/appdata/local/tempのショートカットをデスクトップに作っておくと便利(送られたファイルを触れる)
```


## 使い方
malwareフォルダに解析対象を入れる

srcフォルダで
```bash
python3 submit.py
```

解析が異常終了した場合にコンポーネントを全て落とす方法
```bash
python3 stop.py
```

全てのログ関係を削除する方法
```bash
python3 clean.py
```

### 実行コマンド
python3 submit.py

"please input filename in malware folder for analyse"が返ってきたらファイル名を入力する

解析終了まで待つ

"Continue analysis?"が返ってきたら続ける場合はy，終わる場合はNを入力する

続ける場合はURLが表示されるのでそこからルールの設定を行って，okを入力する

新しいルールに基づいて再度解析が始まるのでこれを繰り返す

### ログ
log/解析ファイル名/タイムスタンプ

中身は

* mitmdump-out.log(外部への通信のログ))
* mitmdump-out.out(外部への通信の出力ファイル))
* mitmdump-to-inetsim.log: inetsimへの通信のログ
* mitmdump-to-inetsim.out: mitmdumpの出力ファイル
* tcpdump.out(解析時のpcapファイル)

## メモ

### 必要な修正
#### cuckooでofficeが立ち上がらない問題の修正  
~/.cuckoo/analyzer/windows/lib/api/process.py

```python
# patch for Win10, office16 not working
​if mode=="office":
​   subprocess.Popen([path, args])
```  
を追記

#### cuckooで強制的にタイムアウトまで解析させる
~/.cuckoo/analyzer/windows/analyzer.py
```python
if not self.process_list.pids:
    log.info("Process list is empty, "
                "terminating analysis.")
    break
``` 
をコメントアウトした

### 遭遇エラー例と解決策メモ
エラー: su-main.pyを起動した際にunboundがポートを捕まえられずにエラーを吐いた  
解決策: vboxnet0が消えている場合があり，その場合はunboundがエラーを吐くので，一度VirtualBoxを起動して落とすと復活する

エラー: CuckooStartupError: The rooter is required but it is either not running or it has been configured to a different Unix socket path. Please refer to the documentation on working with the rooter.
解決策: VM再起動時にcuckoo rooterを再起動する必要があるので
```bash
cuckoo rooter --sudo
```
を実行する．

エラー: You don't have permission to capture on that device
解決策: CuckooのTcpdumpの設定がリセットされている(https://cuckoo.readthedocs.io/en/0.4.1/installation/host/requirements/)

エラー: Unboundからinetsimに繋がらない(server fail)
解決策: 
```bash
/var/log/syslog | grep unbound
```
にfailed to prime trust anchorとあれば，DNS SECが原因

unbound/unbound.conf.d/root-auto-trust-anchor-file.confをコメントアウトする

