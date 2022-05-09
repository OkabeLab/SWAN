from django.db import models
from django.utils.timezone import localtime

class Protocol(models.Model):
    name = models.CharField(max_length=16)

    def __str__(self):
        return self.name
    
class Analysis(models.Model):
    date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        # return localtime(self.date).strftime('%Y-%m-%d %H:%M')
        return "Analysis ID: " + str(self.id)
    
class Packet(models.Model):
    timestamp = models.DateTimeField()
    analysis = models.ForeignKey(Analysis, on_delete=models.CASCADE)
    protocol = models.ForeignKey(Protocol, on_delete=models.CASCADE)
    src_ip = models.GenericIPAddressField()
    src_port = models.IntegerField()
    dst_ip = models.GenericIPAddressField()
    dst_port = models.IntegerField()
    dns_query = models.CharField(max_length=256, blank=True, null=True)
    dns_responce = models.GenericIPAddressField(blank=True, null=True)
    info = models.TextField()

    def __str__(self):
        return str(self.id)

class DNSPolicy(models.Model):
    analysis = models.ForeignKey(Analysis, on_delete=models.CASCADE)
    domain = models.CharField(max_length=256)
    POLICY_CHOICES = [("SM", "Simulate"), ("UB", "Unbound"),]
    policy = models.CharField(max_length=2, choices=POLICY_CHOICES, default="SM",)
    def __str__(self):
        return str(self.id)

class HTTPPolicy(models.Model):
    analysis = models.ForeignKey(Analysis, on_delete=models.CASCADE)
    dst_ip = models.GenericIPAddressField()
    dst_port = models.IntegerField()
    counter = models.IntegerField()
    POLICY_CHOICES = [("SM", "Simulate"), ("PX", "Proxy"), ("IV", "INVALID")]
    policy = models.CharField(max_length=2, choices=POLICY_CHOICES, default="SM",)
    def __str__(self):
        return str(self.id)

class TLSPolicy(models.Model):
    analysis = models.ForeignKey(Analysis, on_delete=models.CASCADE)
    dst_ip = models.GenericIPAddressField()
    dst_port = models.IntegerField()
    counter = models.IntegerField()
    POLICY_CHOICES = [("SM", "Simulate"), ("PX", "Proxy"), ("IV", "INVALID")]
    policy = models.CharField(max_length=2, choices=POLICY_CHOICES, default="SM",)
    def __str__(self):
        return str(self.id)

class UploadFile(models.Model):
    analysis = models.ForeignKey(Analysis, on_delete=models.CASCADE)
    file_path = models.TextField(default="")
    def __str__(self):
        return self.file_path
