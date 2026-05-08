from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name="dashboard"),
    path('input/', views.ioc_input, name="ioc_input"),
    path('results/', views.results, name="results"),
    path('charts/', views.charts, name="charts"),
    path('dnsgraph/', views.dns_graph_page, name="dnsgraph"),

    path('export/', views.export_csv, name="export_csv"),
    path('api/dnsgraph/', views.dns_graph_api),
]