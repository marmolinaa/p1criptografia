from django.urls import path

from . import views

urlpatterns = [
    path('', views.GUI, name='GUI'),

    path('EDA/', views.EDA, name='EDA'),
    path('EDA/numericas', views.EDAnumericas, name='EDAnumericas'),
    path('EDA/nominales', views.EDAnominales, name='EDAnominales'),
    
    path('PCA/', views.PCAf, name='PCA'),
    path('PCA/estandar/<key>', views.PCAestandar, name='PCAestandar'),

    path('Clustering/', views.Clustering, name='Clustering'),
    path('Clustering/matriz/<key>', views.ClusteringMat, name='ClusteringMat'),
    path('Clustering/Kmeans', views.ClusteringKmeans, name='ClusteringKmeans'),

    path('Regresion/', views.Regresion, name='Regresion'),
    path('Regresion/matriz/<key>', views.RegresionMat, name='RegresionMat')
]