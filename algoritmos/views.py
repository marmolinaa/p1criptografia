from django.shortcuts import render
from django.http import HttpResponse
from django.core.files import File

import pandas as pd # Manipulación y análisi de datos
import numpy as np # Para crear vectores matrices de n dimensiones
import matplotlib.pyplot as plt # Para genenar gráficos
import seaborn as sns # Para vasialización de datos

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
    BASE_DIR = Path(__file__).resolve().parent.parent
    x = os.path.join(BASE_DIR, 'files')

    listd=[]#Lista del parametro d
    listQX=[]#Lista del punto X
    listQY=[]#Lista del punto Y
    listMsg=[]#Lista de los mensajes
    listR=[]#Lista de firmas R
    listS=[]#Lista de firmas S

    archivo = open(x+"\ECC_P521_GEN.txt","r")
    
    for linea in archivo.readlines():
        if "Qx = " in linea:#Lee el punto X del archivo
            fQx = linea.lstrip("Qx = ")
            listQX.append(fQx.rstrip("\n"))
        elif "Qy = " in linea:#Lee el punto Y del archivo
            fQy = linea.lstrip("Qy = ")
            listQY.append(fQy.rstrip("\n"))
        elif "Msg = " in linea:#Lee los mensajes del archivo
            m = linea.lstrip("Msg = ")
            listMsg.append(m.rstrip("\n"))
        elif "R = " in linea:#Lee la firma R del archivo
            fr = linea.lstrip("R = ")
            listR.append(fr.rstrip("\n"))
        elif "S = " in linea:#Lee la firma s del archivo
            fs = linea.lstrip("S = ")
            listS.append(fs.rstrip("\n"))
        elif "d = " in linea:#Lee el parametro Y del archivo
            fd = linea.lstrip("d = ")
            listd.append(fd.rstrip("\n"))
    archivo.close()
    context = {
        'timeGenECC_521': 'timeGenECC_521',
        'timeVerECC_521': 'timeVerECC_521',
        'timeGenECC_384': 'timeGenECC_384',
        'timeVerECC_384': 'timeVerECC_384',
        'listvector': 'listvector',
        'timelist':'timelist'
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
    plt.switch_backend('agg')
    return render(request, 'EDAnumericas.html', context)

def EDAnominales(request):
    BASE_DIR = Path(__file__).resolve().parent.parent
    x = os.path.join(BASE_DIR, 'files')
    DatosVac = pd.read_csv(x+'/melb_data.csv')

    # Características nominales
    for col in DatosVac.select_dtypes(include='object'):
        if DatosVac[col].nunique() < 26:
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

def PCA(request):
    BASE_DIR = Path(__file__).resolve().parent.parent
    x = os.path.join(BASE_DIR, 'files')
    DatosVac = pd.read_csv(x+'/country_vaccinations.csv')
    DatosVac.hist(figsize=(14,14), xrot=45)

    DatosVacHTML = DatosVac.to_html()

    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    image = 'data:image/png;base64,' + urllib.parse.quote(string)

    context = {
        'DatosVac': DatosVac,
        'DatosVacHTML': DatosVacHTML,
        'figure' : image
    }
    return render(request, 'PCA.html', context)

def Clustering(request):
    BASE_DIR = Path(__file__).resolve().parent.parent
    x = os.path.join(BASE_DIR, 'files')
    DatosVac = pd.read_csv(x+'/country_vaccinations.csv')
    DatosVac.hist(figsize=(14,14), xrot=45)

    DatosVacHTML = DatosVac.to_html()

    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    image = 'data:image/png;base64,' + urllib.parse.quote(string)

    context = {
        'DatosVac': DatosVac,
        'DatosVacHTML': DatosVacHTML,
        'figure' : image
    }
    return render(request, 'Clustering.html', context)

def Regresion(request):
    BASE_DIR = Path(__file__).resolve().parent.parent
    x = os.path.join(BASE_DIR, 'files')
    DatosVac = pd.read_csv(x+'/country_vaccinations.csv')
    DatosVac.hist(figsize=(14,14), xrot=45)

    DatosVacHTML = DatosVac.to_html()

    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    image = 'data:image/png;base64,' + urllib.parse.quote(string)

    context = {
        'DatosVac': DatosVac,
        'DatosVacHTML': DatosVacHTML,
        'figure' : image
    }

    return render(request, 'Regresion.html', context)