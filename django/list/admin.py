from django.contrib import admin
from . import models


@admin.register(models.Protocol)
class ProtocolAdmin(admin.ModelAdmin):
    pass

@admin.register(models.Analysis)
class AnalysisAdmin(admin.ModelAdmin):
    pass


@admin.register(models.Packet)
class PacketAdmin(admin.ModelAdmin):
    pass

@admin.register(models.DNSPolicy)
class PacketAdmin(admin.ModelAdmin):
    pass

@admin.register(models.HTTPPolicy)
class PacketAdmin(admin.ModelAdmin):
    pass

@admin.register(models.TLSPolicy)
class PacketAdmin(admin.ModelAdmin):
    pass

