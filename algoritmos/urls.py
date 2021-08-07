from django.urls import path

from . import views

urlpatterns = [
    path('', views.GUI, name='GUI'),
    path('EDA/', views.EDA, name='EDA'),
    path('PCA/', views.PCA, name='PCA'),
    path('Clustering/', views.Clustering, name='Clustering'),
    path('Regresion/', views.Regresion, name='Regresion'),
]