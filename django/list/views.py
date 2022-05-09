from django.views.generic import View, ListView
from django.shortcuts import get_object_or_404, render
from django.http import FileResponse
from .models import DNSPolicy, HTTPPolicy, TLSPolicy, Protocol, Analysis, Packet, UploadFile
from mysite.settings import MEDIA_ROOT

class DownloadPcapView(View):
    def get(self, request, *args, **kwargs):
        upload_file = get_object_or_404(UploadFile, pk=self.kwargs["pk"])
        filename = upload_file.file_path+".pcap"
        filepath = MEDIA_ROOT+filename
        return FileResponse(open(filepath, "rb"), as_attachment=True, filename=filename)

class DownloadMitmView(View):
    def get(self, request, *args, **kwargs):
        upload_file = get_object_or_404(UploadFile, pk=self.kwargs["pk"])
        filename = upload_file.file_path+".log"
        filepath = MEDIA_ROOT+filename
        return FileResponse(open(filepath, "rb"), as_attachment=True, filename=filename)

class ProtocolListView(ListView):
    model = Analysis
    template_name = "protocol_list.html"

    def get_context_data(self):
        context = super().get_context_data()
        context["page_title"] = 'hoge'
        return context
    
class AnalysisListView(ListView):
    model = Analysis
    template_name = "analysis_list.html"

    def get_context_data(self):
        context = super().get_context_data()
        context["page_title"] = 'Analysis list'
        return context

class PacketListView(ListView):
    model = Packet
    template_name = "packet_list.html"

    def get(self, request, *args, **kwargs):
        # 既知のコンテキストの代入
        self.object_list = self.get_queryset()
        context = self.get_context_data()

        dlist = context["dlist"]
        h_list = context["h_list"]
        h_list_counter = context["h_list_counter"]
        t_list = context["t_list"]
        t_list_counter = context["t_list_counter"]

        # dnsのポリシーをコンテキストに代入
        dlist_control = []
        for d in dlist:
            obj, created = DNSPolicy.objects.get_or_create(
                analysis_id=self.kwargs['pk'], domain=d,
                defaults={"policy": "SM"},
            )
            dlist_control.append(getattr(obj, "policy"))
        context["dlist_control"] = dlist_control

        # httpのポリシーをコンテキストに代入
        h_list_control = []
        for h, hc in zip(h_list, h_list_counter):
            packetq = Packet.objects.filter(analysis_id=self.kwargs['pk'], id=h)
            for packet in packetq:
                if hc == 0:
                    obj, created = HTTPPolicy.objects.get_or_create(
                        analysis_id=self.kwargs['pk'], dst_ip=str(packet.dst_ip), dst_port=str(packet.dst_port), counter=hc,
                        defaults={"policy": "IV"},
                    )
                else:
                    obj, created = HTTPPolicy.objects.get_or_create(
                        analysis_id=self.kwargs['pk'], dst_ip=str(packet.dst_ip), dst_port=str(packet.dst_port), counter=hc,
                        defaults={"policy": "SM"},
                    )
                h_list_control.append(getattr(obj, "policy"))
        context["h_list_control"] = h_list_control

        # tlsのポリシーをコンテキストに代入
        t_list_control = []
        for t, tc in zip(t_list, t_list_counter):
            packetq = Packet.objects.filter(analysis_id=self.kwargs['pk'], id=t)
            for packet in packetq:
                # ALL設定有効でなければInvalid
                if tc == 0:
                    obj, created = TLSPolicy.objects.get_or_create(
                        analysis_id=self.kwargs['pk'], dst_ip=str(packet.dst_ip), dst_port=str(packet.dst_port), counter=tc,
                        defaults={"policy": "IV"},
                    )
                else:
                    obj, created = TLSPolicy.objects.get_or_create(
                        analysis_id=self.kwargs['pk'], dst_ip=str(packet.dst_ip), dst_port=str(packet.dst_port), counter=tc,
                        defaults={"policy": "SM"},
                    )
                t_list_control.append(getattr(obj, "policy"))
        context["t_list_control"] = t_list_control
        # dnsの要素をzipしてコンテキストに代入しておく
        context["dns_zip"] = zip(dlist, dlist_control)
        # httpの要素をzipしてコンテキストに代入しておく
        context["http_zip"] = zip(h_list, h_list_counter, h_list_control)
        # tlsの要素をzipしてコンテキストに代入しておく
        context["tls_zip"] = zip(t_list, t_list_counter, t_list_control)

        return render(request, self.template_name, context)

    def post(self, request, *args, **kwargs):
        # 既知のコンテキストの代入
        self.object_list = self.get_queryset()
        context = self.get_context_data()
        dlist = context["dlist"]
        h_list = context["h_list"]
        h_list_counter = context["h_list_counter"]
        t_list = context["t_list"]
        t_list_counter = context["t_list_counter"]

        # htmlのapplyボタンに書き込んだ名前でどのボタンが押されたかを識別する
        # dns policyの更新
        if "button-dns-policy" in request.POST:
            # domainごとに
            for d in dlist:
                # policyを取得
                p = request.POST.get(d)
                obj, created = DNSPolicy.objects.update_or_create(
                    analysis_id=self.kwargs['pk'], domain=d,
                    defaults={"policy": p},
                )
        # http policyの更新
        elif "button-http-policy" in request.POST:
            # print(request.POST)
            for h, hc in zip(h_list, h_list_counter):
                packetq = Packet.objects.filter(analysis_id=self.kwargs['pk'], id=h)
                for packet in packetq:
                    # ALL設定有効でなければInvalid
                    if hc == 0 and request.POST.get(str(packet.dst_ip)+"-"+str(packet.dst_port)+"-all") == None:
                        p = "IV"
                    else:
                        p = request.POST.get(str(packet.dst_ip)+"-"+str(packet.dst_port)+"-"+str(hc))
                    obj, created = HTTPPolicy.objects.update_or_create(
                        analysis_id=self.kwargs['pk'], dst_ip=str(packet.dst_ip), dst_port=str(packet.dst_port), counter=hc,
                        defaults={"policy": p},
                    )
        # tls policyの更新
        elif "button-tls-policy" in request.POST:
            # print(request.POST)
            for t, tc in zip(t_list, t_list_counter):
                packetq = Packet.objects.filter(analysis_id=self.kwargs['pk'], id=t)
                for packet in packetq:
                    # ALL設定有効でなければInvalid
                    if tc == 0 and request.POST.get(str(packet.dst_ip)+"-"+str(packet.dst_port)+"-all") == None:
                        p = "IV"
                    else:
                        p = request.POST.get(str(packet.dst_ip)+"-"+str(packet.dst_port)+"-"+str(tc))
                    obj, created = TLSPolicy.objects.update_or_create(
                        analysis_id=self.kwargs['pk'], dst_ip=str(packet.dst_ip), dst_port=str(packet.dst_port), counter=tc,
                        defaults={"policy": p},
                    )

        # POSTした場合にもポリシーが表示されるように取得(getと同じ処理)
        # dnsのポリシーをコンテキストに代入
        dlist_control = []
        for d in dlist:
            obj, created = DNSPolicy.objects.get_or_create(
                analysis_id=self.kwargs['pk'], domain=d,
                defaults={"policy": "SM"},
            )
            dlist_control.append(getattr(obj, "policy"))
        context["dlist_control"] = dlist_control

        # httpのポリシーをコンテキストに代入
        h_list_control = []
        for h, hc in zip(h_list, h_list_counter):
            packetq = Packet.objects.filter(analysis_id=self.kwargs['pk'], id=h)
            for packet in packetq:
                if hc == 0:
                    obj, created = HTTPPolicy.objects.get_or_create(
                        analysis_id=self.kwargs['pk'], dst_ip=str(packet.dst_ip), dst_port=str(packet.dst_port), counter=hc,
                        defaults={"policy": "IV"},
                    )
                else:
                    obj, created = HTTPPolicy.objects.get_or_create(
                        analysis_id=self.kwargs['pk'], dst_ip=str(packet.dst_ip), dst_port=str(packet.dst_port), counter=hc,
                        defaults={"policy": "SM"},
                    )
                h_list_control.append(getattr(obj, "policy"))
        context["h_list_control"] = h_list_control

        # tlsのポリシーをコンテキストに代入
        t_list_control = []
        for t, tc in zip(t_list, t_list_counter):
            packetq = Packet.objects.filter(analysis_id=self.kwargs['pk'], id=t)
            for packet in packetq:
                if tc == 0:
                    obj, created = TLSPolicy.objects.get_or_create(
                        analysis_id=self.kwargs['pk'], dst_ip=str(packet.dst_ip), dst_port=str(packet.dst_port), counter=tc,
                        defaults={"policy": "IV"},
                    )
                else:
                    obj, created = TLSPolicy.objects.get_or_create(
                        analysis_id=self.kwargs['pk'], dst_ip=str(packet.dst_ip), dst_port=str(packet.dst_port), counter=tc,
                        defaults={"policy": "SM"},
                    )
                t_list_control.append(getattr(obj, "policy"))
        context["t_list_control"] = t_list_control

        # dnsの要素をzipしてコンテキストに代入しておく
        context["dns_zip"] = zip(dlist, dlist_control)
        # httpの要素をzipしてコンテキストに代入しておく
        context["http_zip"] = zip(h_list, h_list_counter, h_list_control)
        # tlsの要素をzipしてコンテキストに代入しておく
        context["tls_zip"] = zip(t_list, t_list_counter, t_list_control)

        return render(request, self.template_name, context)

    def get_context_data(self):
        context = super().get_context_data()
        context["page_title"] = 'Packet list'
        # analysis idを取得
        a_id = self.kwargs['pk']
        context["analysis_key"] = a_id
        packet_file = UploadFile.objects.filter(analysis_id=a_id).first()
        if packet_file != None:
            context["packet_file"] = packet_file

        # queryが投げられたドメインのリストをコンテキストに追加
        dlist = []
        query_list = Packet.objects.filter(analysis_id=a_id).exclude(dns_query="").all()
        for domain in query_list:
            dlist.append(domain.dns_query)
        # 順番を保持して重複を削除
        dlist = list(sorted(set(dlist), key=dlist.index))
        context["dlist"] = dlist

        # responceが存在するquery-responceのリストをコンテキストに追加
        q_list = []
        r_list = []
        qr_list = []
        for pkt in query_list:
            if pkt.dns_responce != "":
                # q_list.append(pkt.dns_query)
                # r_list.append(pkt.dns_responce)
                qr_list.append((pkt.dns_query, pkt.dns_responce))
        # q_list = list(sorted(set(q_list), key=q_list.index))
        # r_list = list(sorted(set(r_list), key=r_list.index))
        qr_list = list(sorted(set(qr_list), key=qr_list.index))
        # context["q_list"] = q_list
        # context["r_list"] = r_list
        context["qr_list"] = qr_list

        # 192.168.56.101宛は受信パケットなので除く
        # 192.168.56.1宛はsimulateなので除く
        http_list = Packet.objects.filter(analysis_id=a_id, protocol=2).exclude(dst_ip="192.168.56.101").exclude(dst_ip="192.168.56.1").all()
        h_list=[]
        h_list_counter=[]
        dst_ip_check = ""
        dst_port_check = ""
        i = 0
        for pkt in http_list:
            if dst_ip_check!=pkt.dst_ip or dst_port_check!=pkt.dst_port:
                # counter=0を挿入しておく(ALL設定用)
                h_list_counter.append(0)
                h_list.append(pkt.id)
                i = 1
                dst_ip_check = pkt.dst_ip
                dst_port_check = pkt.dst_port
                h_list_counter.append(i)
            else:
                i += 1
                h_list_counter.append(i)
            h_list.append(pkt.id)
        context["h_list"] = h_list
        context["h_list_counter"] = h_list_counter

        # 192.168.56.101宛は受信パケットなので除く
        # 192.168.56.1宛はsimulateなので除く
        tls_list = Packet.objects.filter(analysis_id=a_id, protocol=3).exclude(dst_ip="192.168.56.101").exclude(dst_ip="192.168.56.1").order_by("dst_ip", "dst_port").all()
        t_list=[]
        t_list_counter=[]
        dst_ip_check = ""
        dst_port_check = ""
        i = 0
        for pkt in tls_list:
            if dst_ip_check!=pkt.dst_ip or dst_port_check!=pkt.dst_port:
                # counter=0を挿入しておく(ALL設定用)
                t_list_counter.append(0)
                t_list.append(pkt.id)
                i = 1
                dst_ip_check = pkt.dst_ip
                dst_port_check = pkt.dst_port
                t_list_counter.append(i)
            else:
                i += 1
                t_list_counter.append(i)
            t_list.append(pkt.id)
        context["t_list"] = t_list
        context["t_list_counter"] = t_list_counter

        return context

