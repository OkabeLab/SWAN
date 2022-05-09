from django.contrib import admin
from django.urls import include, path
from list import views

urlpatterns = [
    path('', include('list.urls')),
    path('list/', include('list.urls')),
    path('admin/', admin.site.urls),
    path("download/pcap/<int:pk>/", views.DownloadPcapView.as_view(), name="download"),
    path("download/mitm/<int:pk>/", views.DownloadMitmView.as_view(), name="download"),
]