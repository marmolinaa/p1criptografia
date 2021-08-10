from django.shortcuts import render
from django.http import HttpResponse
from django.core.files import File

import pandas as pd # Manipulación y análisi de datos
import numpy as np # Para crear vectores matrices de n dimensiones
import matplotlib.pyplot as plt # Para genenar gráficos
import seaborn as sns # Para vasialización de datos

from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans
from sklearn.metrics import pairwise_distances_argmin_min
from kneed import KneeLocator

from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
from matplotlib.figure import Figure


from time import time
from pathlib import Path
import os
import io
import urllib
import base64
import json



def GUI(request):
    context = {
        'context': 'context'
    }
    return render(request, 'GUI.html', context)

def EDA(request):
    BASE_DIR = Path(__file__).resolve().parent.parent
    x = os.path.join(BASE_DIR, 'files')
    dataEDA = pd.read_csv(x+'/melb_data.csv')

    headTen = dataEDA.head(10) # Regresa los prieros 10 valores
    headTenHTML = headTen.to_html()
    datosFaltantes = dataEDA.isnull().sum() # Identificación de datos faltantes.
    datosFaltantesDic = datosFaltantes.to_dict()
    datatype = dataEDA.dtypes
    datatypeDic = datatype.to_dict()
    dataCorr = dataEDA.corr()
    dataCorrHTML = dataCorr.to_html()

    plt.figure(figsize=(14,7))
    sns.heatmap(dataEDA.corr(), cmap='RdBu_r', annot=True)
    
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    correlaciones = 'data:image/png;base64,' + urllib.parse.quote(string)
    
    context = {
        'headTenHTML' : headTenHTML,
        'datosFaltantesDic': datosFaltantesDic,
        'datatypeDic': datatypeDic,
        'dataCorrHTML': dataCorrHTML,
        'correlaciones':correlaciones
    }
    return render(request, 'EDA.html', context)

def EDAnumericas(request):
    BASE_DIR = Path(__file__).resolve().parent.parent
    x = os.path.join(BASE_DIR, 'files')
    DatosVac = pd.read_csv(x+'/melb_data.csv')

    # Características numéricas
    DatosVac.hist(figsize=(14,14), xrot=45)
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    CaracNumericas = 'data:image/png;base64,' + urllib.parse.quote(string)

    context = {
        'CaracNumericas' : CaracNumericas
    }
    return render(request, 'EDAnumericas.html', context)

def EDAnominales(request):
    BASE_DIR = Path(__file__).resolve().parent.parent
    x = os.path.join(BASE_DIR, 'files')
    DatosVac = pd.read_csv(x+'/melb_data.csv')

    # Características nominales
    for col in DatosVac.select_dtypes(include='object'):
        if DatosVac[col].nunique() < 10:
            sns.countplot(y=col, data=DatosVac)
    
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    CaracNominales = 'data:image/png;base64,' + urllib.parse.quote(string)

    context = {
        'CaracNominales': CaracNominales
    }
    plt.switch_backend('agg')
    return render(request, 'EDAnominales.html', context)   

def PCAf(request):
    BASE_DIR = Path(__file__).resolve().parent.parent
    x = os.path.join(BASE_DIR, 'files')
    dataPCA = pd.read_csv(x+'/Hipoteca.csv')

    DatosPCAtop = dataPCA.head(10)
    DatosPCAHTMLtop = DatosPCAtop.to_html()
    DatosPCADic = dataPCA.to_dict()
    keysPCA = list(DatosPCADic.keys())

    context = {
        'DatosPCAHTMLtop': DatosPCAHTMLtop,
        'keysPCA': keysPCA
    }
    return render(request, 'PCA.html', context)

def PCAestandar(request, key):
    BASE_DIR = Path(__file__).resolve().parent.parent
    x = os.path.join(BASE_DIR, 'files')
    dataPCA = pd.read_csv(x+'/Hipoteca.csv')

    normalizar = StandardScaler()                       # Se instancia el objeto StandardScaler 
    MdataPCA = dataPCA.drop([key], axis=1)      # Se quita la variable dependiente "Y"
    normalizar.fit(MdataPCA)                           # Se calcula la media y desviación para cada dimensión
    MNormalizada = normalizar.transform(MdataPCA)

    matNor = pd.DataFrame(MNormalizada, columns=MdataPCA.columns)
    matNotTop = matNor.head(10)
    matNorHTML = matNotTop.to_html()

    Componentes = PCA(n_components=9)
    Componentes.fit(MNormalizada)
    X_Comp = Componentes.transform(MNormalizada)

    diensiones = pd.DataFrame(X_Comp)
    diensionesTop = diensiones.head(10)
    diensionesHTML = diensionesTop.to_html()

    vectores = Componentes.components_
    vectoresList = vectores.tolist()

    Varianza = Componentes.explained_variance_ratio_

    plt.plot(np.cumsum(Componentes.explained_variance_ratio_))
    plt.xlabel('Numero de componentes')
    plt.ylabel('Varianza acumulada')
    plt.grid()

    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    fig = 'data:image/png;base64,' + urllib.parse.quote(string)

    relUno = pd.DataFrame(abs(Componentes.components_))
    relUnoHTML = relUno.to_html()
    CargasComponentes = pd.DataFrame(abs(Componentes.components_), columns=MdataPCA.columns)
    CargasComponentesHTML = CargasComponentes.to_html()

    context = {
        'MNormalizada': MNormalizada.shape,
        'matNorHTML':matNorHTML,
        'diensionesHTML': diensionesHTML,
        'vectoresList': vectoresList,
        'Eigenvalues': Varianza,
        'Acumulada': sum(Varianza[0:5]),
        'fig': fig,
        'relUnoHTML':relUnoHTML,
        'CargasComponentesHTML': CargasComponentesHTML
    }
    return render(request, 'PCAestandar.html', context)

def Clustering(request):
    BASE_DIR = Path(__file__).resolve().parent.parent
    x = os.path.join(BASE_DIR, 'files')
    dataClus = pd.read_csv(x+'/Hipoteca.csv')

    DatosClusTop = dataClus.head(10)
    DatosClusHTMLtop = DatosClusTop.to_html()
    DatosClusDic = dataClus.to_dict()
    keysClus = list(DatosClusDic.keys())

    plt.figure(figsize=(14,7))
    sns.heatmap(dataClus.corr(), cmap='RdBu_r', annot=True)
    
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    correlaciones = 'data:image/png;base64,' + urllib.parse.quote(string)

    context = {
        'DatosClusHTMLtop': DatosClusHTMLtop,
        'keysClus': keysClus,
        'correlaciones':correlaciones
    }
    return render(request, 'Clustering.html', context)

def ClusteringMat(request, key):
    BASE_DIR = Path(__file__).resolve().parent.parent
    x = os.path.join(BASE_DIR, 'files')
    dataClus = pd.read_csv(x+'/Hipoteca.csv')

    sns.pairplot(dataClus, hue=key)
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    matClustering = 'data:image/png;base64,' + urllib.parse.quote(string)

    context = {
        'matClustering': matClustering
    }
    return render(request, 'ClusteringMat.html', context)

def ClusteringKmeans(request):
    BASE_DIR = Path(__file__).resolve().parent.parent
    x = os.path.join(BASE_DIR, 'files')
    dataClus = pd.read_csv(x+'/Hipoteca.csv')

    #Definición de k clusters para K-means
    #Se utiliza random_state para inicializar el generador interno de números aleatorios
    SSE = []
    for i in range(2, 12):
        km = KMeans(n_clusters=i, random_state=0)
        km.fit(dataClus)
        SSE.append(km.inertia_)

    #Se grafica SSE en función de k
    plt.figure(figsize=(10, 7))
    plt.plot(range(2, 12), SSE, marker='o')
    plt.xlabel('Cantidad de clusters *k*')
    plt.ylabel('SSE')
    plt.title('Elbow Method')

    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    kmeans = 'data:image/png;base64,' + urllib.parse.quote(string)

    kl = KneeLocator(range(2, 12), SSE, curve="convex", direction="decreasing")
    codo = kl.elbow

    context = {
        'kmeans': kmeans,
        'codo': codo
    }
    return render(request, 'ClusteringKmeans.html', context)

def Regresion(request):
    BASE_DIR = Path(__file__).resolve().parent.parent
    x = os.path.join(BASE_DIR, 'files')
    dataRegresion = pd.read_csv(x+'/WDBCOriginal.csv')

    DatosRegTop = dataRegresion.head(10)
    DatosRegHTMLtop = DatosRegTop.to_html()
    DatosRegDic = dataRegresion.to_dict()
    keysReg = list(DatosRegDic.keys())

    plt.figure(figsize=(14,7))
    sns.heatmap(dataRegresion.corr(), cmap='RdBu_r', annot=True)
    
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    correlaciones = 'data:image/png;base64,' + urllib.parse.quote(string)

    context = {
        'DatosRegHTMLtop': DatosRegHTMLtop,
        'keysReg': keysReg,
        'correlaciones':correlaciones
    }
    return render(request, 'Regresion.html', context)

def RegresionMat(request, key):
    BASE_DIR = Path(__file__).resolve().parent.parent
    x = os.path.join(BASE_DIR, 'files')
    dataRegresion = pd.read_csv(x+'/WDBCOriginal.csv')

    sns.pairplot(dataRegresion, hue=key)
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    matRegresion = 'data:image/png;base64,' + urllib.parse.quote(string)

    context = {
        'matRegresion': matRegresion
    }
    return render(request, 'RegresionMat.html', context)