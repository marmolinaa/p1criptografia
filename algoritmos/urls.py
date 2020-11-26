from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('aes/', views.aes, name='aes'),
    path('sha/', views.sha, name='sha'),
    path('rca/', views.rca, name='rca'),
    path('dsa/', views.dsa, name='dsa'),
    path('ecdsa/', views.ecdsa, name='ecdsa'),
]