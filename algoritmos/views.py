from django.shortcuts import render
from django.http import HttpResponse
from django.core.files import File

#AES ECB y AES CBC
from Cryptodome.Cipher import AES
#SHA-2 384
from Cryptodome.Hash import SHA384
#SHA-2 512
from Cryptodome.Hash import SHA512
#SHA-3 384
from Cryptodome.Hash import SHA3_384
#SHA-3 512
from Cryptodome.Hash import SHA3_512
#RSA OAEP y PSS
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Signature import pss
#DSA Y ECDSA
from Cryptodome.PublicKey import DSA
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
from Cryptodome.Hash import SHA256
#Para estadística de los resultados y tiempos
import statistics

from time import time
from pathlib import Path
import os



def index(request):
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
    return render(request, 'escritorio.html', context)

def aes(request):
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
    return render(request, 'AES.html', context)

def sha(request):
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

    return render(request, 'SHA.html', context)

def rca(request):
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
    return render(request, 'RCA.html', context)

def dsa(request):
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
    return render(request, 'DSA.html', context)

def ecdsa(request):
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

    return render(request, 'ECDSA.html', context)