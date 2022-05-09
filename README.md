# SWAN(Sandbox with traffic Whitelisting for ANalyzing malware)

## 使い方
(他のユーザでは上手く実行できないかもしれない)

srcに移動

malwareフォルダに解析対象を入れる

### 導入
/etc/unbound/unbound.confに
```bash
include: "/etc/unbound/unbound.conf.d/*.conf"
```
を書き加える．

conf/swan.confの[unbound]conf.d-pathを"/etc/unbound/unbound.conf.d"に変更する．

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

#### cuckooでタイムアウトを待たずに解析が終了してしまう問題の修正
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