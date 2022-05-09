from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from . import views

urlpatterns = [
    path('', views.AnalysisListView.as_view(), name="index"),
    path('analysis/<pk>/', views.PacketListView.as_view(), name="analysis"),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)