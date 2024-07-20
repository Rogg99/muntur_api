from django.shortcuts import render
from django.http import JsonResponse
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from .models import *
from .constances import forms
from .constances import constances  as c
import datetime
import json,base64
import logging
from PIL import Image
import pandas as pd
import numpy as np
import requests
from geopy.distance import geodesic as GD
from geopy.distance import great_circle as GRC
from secrets import token_hex
from django.core.files.storage import FileSystemStorage
from collections import Counter
import random


logger = logging.getLogger('db')


class Point:
    def _init_(self,lon,lat):
        self.lon=lon
        self.lat=lat

def calculateDistance(point1:Point,point2:Point):
    return GRC([point1.lat,point1.lon],[point2.lat,point2.lon]).km*1000
    


@csrf_exempt
def welcomePage(request):
    return render(request,template_name='index.html')

#CRUD views for Token Model
@csrf_exempt
def createToken(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if  request.method == 'POST':
        body={
            'id':request.POST.get("id",''),
            'email':request.POST.get("email",''),
            'password':request.POST.get("password",''),
        }
        payload = json.dumps(body)
        payload = json.loads(payload)
        form = forms.InitToken(payload)
        if form.is_valid() :
            password = form.cleaned_data["password"]
            email = form.cleaned_data["email"]
            try:
                usr = Token()
                usr.id=email
                usr.password = password
                usr.email = email
                usr.save() 
                data["error"] = False
                data["code"] = 0
                data["data"] = {
                            "id":usr.id,
                            "password" : usr.password,
                            "email" : usr.email,
                            "creation_date" : usr.creation_date,
                            }
                status = 200
            except Exception as e :
                data["error"] = True
                data["code"] = -1
                data['description'] = 'Database Writing error occured :' + str(e)
                logger.exception(data["description"])
                status = 300
        elif not form.is_valid():
            status = 400
            data['code'] = -2
            data['error'] = True
            data['description'] = 'Bad datas given '+form.errors.as_text()
            logger.exception(data["description"])
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    
    else:
        status = 400
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method '
        logger.exception(data["description"])
    return JsonResponse(data, status=status)

@csrf_exempt
def refreshToken(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'PUT' or request.method == 'POST':
        payload = json.loads(request.body)
        form = forms.getToken(payload)
        ip = ''
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        if form.is_valid():
            password = form.cleaned_data["password"]
            email = form.cleaned_data["email"]
            usr = Token.objects.filter(email=email).filter(password=password)
            if len(usr)>0:
                usr=usr[0]
                sessions = Session.objects.filter(email=email).filter(ip=ip)
                if len(sessions)==0 or sessions[0].end_time < datetime.datetime.now().timestamp():
                    session = Session()
                    codefin = datetime.datetime.now().timestamp()
                    session.id = str(uuid.uuid4()) + ":"+str(len(User.objects.filter(creation_date=codefin)))
                    session.access = token_hex(100)
                    session.refresh = token_hex(100)
                    session.ip = ip
                    session.email = email
                    now=floor(datetime.datetime.now().timestamp())
                    end_time = (now + (3600*24*30))
                    session.end_time = end_time
                    session.save()
                else :
                    session=sessions[0]

                data["error"] = False
                data["code"] = 0
                data["access"] = session.access
                data["refresh"] = session.refresh
                status = 200
            else:
                data["error"] = True
                data["code"] = -1
                data['description'] = 'No matching Credentials'
                status = 300
        else:
            status = 400
            data['code'] = -2
            data['error'] = True
            data['description'] = 'Bad datas given '+form.errors.as_text()
            logger.exception(data["description"])
    else:
        status = 400
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method '
        logger.exception(data["description"])
    return JsonResponse(data, status=status)

@csrf_exempt
def verifyToken(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'PUT' or request.method == 'POST': 
        payload = json.loads(request.body)
        ip = ''
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        form = forms.verifyTokenIn(payload)
        if form.is_valid() :
            access = form.cleaned_data["access"]
            usr = Token.objects.filter(access=access)
            if len(usr)>0:
                usr=usr[0] 
                if ip in usr.ips.split('#'):
                    data["error"] = False
                    data["code"] = 0
                    data["data"] = {
                            "id":usr.id,
                            "email" : usr.email,
                            "end_time" : usr.end_time,
                            }
                    status = 200
                else:
                    data["error"] = True
                    data["code"] = -1
                    data['description'] = 'No matching Credentials'
                    status = 300
            else:
                data["error"] = True
                data["code"] = -1
                data['description'] = 'No matching Credentials'
                status = 300
        elif not form.is_valid():
                status = 400
                data['code'] = -2
                data['error'] = True
                data['description'] = 'Bad datas given '+form.errors.as_text()
                logger.exception(data["description"])
    else:
        status = 405
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method'
        logger.exception(data["description"])
    return JsonResponse(data, status=status)

@csrf_exempt
def signOut(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'GET':
        payload = json.dumps(request.GET.dict())
        payload = json.loads(payload)
        ip = ''
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        form = forms.verifyTokenIn(payload)
        if form.is_valid() :
            access = form.cleaned_data["access"]
            usr = Token.objects.filter(access=access)
            if len(usr)>0:
                usr=usr[0]
                ips=usr.ips.split('#')
                if ip in usr.ips.split('#'):
                    ips.remove(ip)
                    ips_str = ''
                    for i in range(len(ips)):
                        if i == len(ips)-1:
                            ips_str += ips[i]
                        else :
                            ips_str += ips[i] + '#'
                    usr.ips=ips_str
                    usr.save()
                    data["error"] = False
                    data["code"] = 0
                    data["data"] = ip + ' logged out successfully'
                    logger.info(data["data"])
                    status = 200
                else:
                    data["error"] = True
                    data["code"] = -1
                    data['description'] = 'No matching Credentials'
                    status = 300
            else:
                data["error"] = True
                data["code"] = -1
                data['description'] = 'No matching Credentials'
                status = 300
        elif not form.is_valid():
            status = 400
            data['code'] = -2
            data['error'] = True
            data['description'] = 'Bad datas given '+form.errors.as_text()
            logger.exception(data["description"])
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    else:
        status = 405
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method'
        logger.exception(data["description"])
    return JsonResponse(data, status=status)

@csrf_exempt
def setPassword(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'GET':
        payload = json.dumps(request.GET.dict())
        payload = json.loads(payload)
        form = forms.verifyTokenIn(payload)
        if form.is_valid() :
            email = form.cleaned_data["email"]
            newpassword = form.cleaned_data["newpassword"]
            usr = Token.objects.filter(email=email)
            if len(usr)>0:
                usr=usr[0]
                usr.password=newpassword
                usr.save()
                data["error"] = False
                data["code"] = 0
                data["data"] = ' password out successfully'
                logger.info(data["data"])
                status = 200
            else:
                data["error"] = True
                data["code"] = -1
                data['description'] = 'No matching Credentials'
                status = 300
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Not Authorized to perform this action'
            logger.exception(data["description"] +' tried by Token '+token)
    else:
        status = 405
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method PUT'
        logger.exception(data["description"])
    return JsonResponse(data, status=status)

def verifyTokenIn(token,request):
    #print('verifying user : ' + token)
    ip = ''
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    toks = Session.objects.filter(access=token.replace('Bearer ',''))
    if len(toks)>0:
        usr=toks[0]
        #print(ip+' ----- '+usr.ips)
        if ip == usr.ip:
            return True
        else:
            return False
    else :
        return False 



#CRUD views for User Model
@csrf_exempt
def createUser(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'PUT' or request.method == 'POST':
        
        ip = ''
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        try:
            payload = json.loads(request.body)
            form = forms.InitUser(payload)
            if form.is_valid() :
                nom = form.cleaned_data["nom"]
                prenom = form.cleaned_data["prenom"]
                email = form.cleaned_data["email"]
                password = form.cleaned_data["password"]
                photo = form.cleaned_data["photo"]
                sexe = form.cleaned_data["sexe"]
                telephone = form.cleaned_data["telephone"]
                ville = form.cleaned_data["ville"]
                pays = form.cleaned_data["pays"]
                try:
                    token = Token()
                    token.id=email
                    token.password = password
                    token.email = email
                    token.save() 
                    
                    session = Session()
                    codefin = datetime.datetime.now().timestamp()
                    session.id = str(uuid.uuid4()) + ":"+str(len(User.objects.filter(creation_date=codefin)))
                    session.access = token_hex(100)
                    session.refresh = token_hex(100)
                    session.ip = ip
                    session.email = email
                    now=floor(datetime.datetime.now().timestamp())
                    end_time = (now + (3600*24*30))
                    session.end_time = end_time
                    session.save()
                    
                    usr = User()
                    # print(floor(datetime.datetime.now().timestamp()))
                    codefin = datetime.datetime.now().timestamp()
                    usr.id = str(uuid.uuid4()) + ":"+str(len(User.objects.filter(creation_date=codefin)))
                    usr.nom = nom
                    usr.prenom = prenom
                    usr.email = email
                    usr.photo = photo
                    usr.sexe = sexe
                    usr.telephone = telephone
                    usr.ville = ville
                    usr.pays = pays
                    usr.save() 
                    data["error"] = False
                    data["code"] = 0
                    data["data"] = {
                                "id":usr.id,
                                "nom" : usr.nom,
                                "prenom" : usr.prenom,
                                "email" : usr.email,
                                "photo" : usr.photo,
                                "sexe" : usr.sexe,
                                "telephone" : usr.telephone,
                                }
                    status = 200
                    logger.info('New User created successfully')
                except Exception as e :
                    data["error"] = True
                    data["code"] = -1
                    data['description'] = 'Database Writing error occured :' + str(e)
                    status = 302
                    logger.exception(e)
            elif not form.is_valid():
                status = 400
                data['code'] = -2
                data['error'] = True
                data['description'] = 'Bad datas given '+ form.errors.as_text()
                logger.exception(data['description'])
        except  Exception as e:
            status = 500
            data['code'] = -4
            data['error'] = True
            data['description'] = str(e)
            logger.exception(e)
    else:
        status = 400
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method GET'
        logger.exception(data['description'])
    return JsonResponse(data, status=status)

@csrf_exempt
def updateUser(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'PUT' or request.method == 'POST':
        token=request.META['HTTP_AUTHORIZATION']
        payload = json.loads(request.body)
        form = forms.InitUser(payload)
        #print(token)
        if verifyTokenIn(token=token,request=request) and form.is_valid():

            nom = form.cleaned_data["nom"]
            prenom = form.cleaned_data["prenom"]
            email = form.cleaned_data["email"]
            photo = form.cleaned_data["photo"]
            sexe = form.cleaned_data["sexe"]
            cni = form.cleaned_data["cni"]
            telephone = form.cleaned_data["telephone"]
            try:
                usr = User.objects.get(id=id)
                usr.nom = nom
                usr.prenom = prenom
                usr.email = email
                usr.photo = photo
                usr.sexe = sexe
                usr.telephone = telephone
                usr.save() 
                data["error"] = False
                data["code"] = 0
                data["data"] = {
                                "id":usr.id,
                                "nom" : usr.nom,
                                "prenom" : usr.prenom,
                                "email" : usr.email,
                                "creation_date" : usr.creation_date,
                            }
                data['error']= False
                status = 200
                logger.info('User updated successfully')
            except Exception as e :
                data["error"] = True
                data["code"] = -1
                data['description'] = 'Database Writing error occured :' + str(e)
                status = 300
                logger.exception(data["description"])
        elif not form.is_valid():
            status = 400
            data['code'] = -2
            data['error'] = True
            data['description'] = 'Bad datas given '+form.errors.as_text()
            logger.exception(data["description"])
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    else:
        status = 400
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method GET'
        logger.exception(data["description"])
    return JsonResponse(data, status=status)

@csrf_exempt
def getUser(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'GET':
        token=request.META['HTTP_AUTHORIZATION']  
        payload = json.dumps(request.GET.dict())
        payload = json.loads(payload)
        print(payload)
        form = forms.getObject(payload)
        if verifyTokenIn(token=token,request=request) and form.is_valid() :
            id = form.cleaned_data["id"]
            usr = User.objects.get(id=id)
            data["error"] = False
            data["code"] = 0
            data["data"] = {
                    "id":usr.id,
                    "nom" : usr.nom,
                    "prenom" : usr.prenom,
                    "email" : usr.email,
                    "photo" : usr.photo,
                    "sexe" : usr.sexe,
                    "date_naissance" : usr.date_naissance,
                    "type" : usr.type,
                    "telephone" : usr.telephone,
                    "ville" : usr.ville,
                    "pays" : usr.pays,
                    "creation_date" : usr.creation_date,
                    }
            status = 200
        elif not form.is_valid():
                status = 400
                data['code'] = -2
                data['error'] = True
                data['description'] = 'Bad datas given '+form.errors.as_text()
                logger.exception(data["description"])
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    else:
        status = 405
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method POST'
        logger.exception(data["description"])
    return JsonResponse(data, status=status)

@csrf_exempt
def getUserWithEmailandPwd(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'GET':
        token=request.META['HTTP_AUTHORIZATION']  
        payload = json.dumps(request.GET.dict())
        payload = json.loads(payload)
        print(payload)
        form = forms.getUserwithemail(payload)
        if verifyTokenIn(token=token,request=request) and form.is_valid() :
            email = form.cleaned_data["email"]
            try:
                usr = User.objects.get(email=email)
                data["error"] = False
                data["code"] = 0
                data["data"] = {
                        "id":usr.id,
                        "nom" : usr.nom,
                        "prenom" : usr.prenom,
                        "email" : usr.email,
                        "photo" : usr.photo,
                        "sexe" : usr.sexe,
                        "date_naissance" : usr.date_naissance,
                        "type" : usr.type,
                        "ville" : usr.ville,
                        "pays" : usr.pays,
                        "telephone" : usr.telephone,
                        "creation_date" : usr.creation_date,
                        }
                status = 200
            except Exception as e:
                status = 300
                data['code'] = -1
                data['error'] = True
                data['description'] = 'No matching account found '+ str(e)
                print(str(e))
                logger.exception(data["description"])

        elif not form.is_valid():
                status = 400
                data['code'] = -2
                data['error'] = True
                data['description'] = 'Bad datas given '+form.errors.as_text()
                logger.exception(data["description"])
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    else:
        status = 405
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method POST'
        logger.exception(data["description"])
    return JsonResponse(data, status=status)

@csrf_exempt
def deleteUser(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'GET':
        token=request.META['HTTP_AUTHORIZATION']  
        payload = json.dumps(request.GET.dict())
        payload = json.loads(payload)
        print(payload)
        form = forms.getUser(payload)
        if verifyTokenIn(token=token,request=request) and form.is_valid() :
            User.objects.delete(id=id)
            data["error"] = False
            data["code"] = 0
            data["data"] = id + ' deleted successfully'
            status = 200
        elif not form.is_valid():
                status = 400
                data['code'] = -2
                data['error'] = True
                data['description'] = 'Bad datas given '+form.errors.as_text()
                logger.exception(data["description"])
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    else:
        status = 405
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method POST'
        logger.exception(data["description"])
    return JsonResponse(data, status=status)


#CRUD views for Garage Model
@csrf_exempt
def createGarage(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'POST':
        token=request.META['HTTP_AUTHORIZATION']
        body={
            'id':request.POST.get("id",''),
            'nom':request.POST.get("nom",''),
            'prenom':request.POST.get("prenom",''),
            'prenom':request.POST.get("prenom",''),
            'email':request.POST.get("email",''),
            'sexe':request.POST.get("sexe",''),
            'date_naissance':request.POST.get("date_naissance",''),
            'cni':request.POST.get("cni",''),
            'numero_ce':request.POST.get("numero_ce",''),
            'telephone':request.POST.get("telephone",''),
            'parrain':request.POST.get("parrain",''),
            'commune':request.POST.get("commune",''),
            'departement_org':request.POST.get("departement_org",''),
            'departement':request.POST.get("departement",''),
            'region':request.POST.get("region",''),
            'pays':request.POST.get("pays",''),
            'edition':request.POST.get("edition",''),
            'sympathisant':request.POST.get("sympathisant",''),
            'photo':request.POST.get("photo",''),
        }
        payload = json.dumps(body)
        payload = json.loads(payload)
        request_file = request.FILES['image'] if 'image' in request.FILES else None
        form = forms.InitGarage(payload)
        if verifyTokenIn(token=token,request=request) and form.is_valid() and request_file:
            fs = FileSystemStorage()
            size = 300, 170
            filename = form.cleaned_data["photo"]
            newfilename=filename.split('.')[0] + '_' + str(int(datetime.datetime.now().timestamp()))+'.'+filename.split('.')[1]
            file = fs.save('images/big/'+newfilename, request_file)
            img = Image.open(settings.MEDIA_ROOT+'/images/big/'+file)
            img = img.resize(size, Image.Resampling.LANCZOS)
            img.save(settings.MEDIA_ROOT+'/'+file)
            fileurl = fs.url(file)

            id = form.cleaned_data["id"]
            nom = form.cleaned_data["nom"]
            prenom = form.cleaned_data["prenom"]
            email = form.cleaned_data["email"]
            sexe = form.cleaned_data["sexe"]
            date_naissance = form.cleaned_data["date_naissance"]
            cni = form.cleaned_data["cni"]
            numero_ce = form.cleaned_data["numero_ce"]
            telephone = form.cleaned_data["telephone"]
            parrain = form.cleaned_data["parrain"]
            commune = form.cleaned_data["commune"]
            departement_org = form.cleaned_data["departement_org"]
            departement = form.cleaned_data["departement"]
            region = form.cleaned_data["region"]
            edition = form.cleaned_data["edition"]
            pays = form.cleaned_data["pays"]
            sympathisant = form.cleaned_data["sympathisant"]
            try:
                usr = Garage()
                usr.id=id
                if id=='auto' or len(id)<10:
                    codefin = floor(datetime.datetime.now().timestamp())
                    usr.id = str(uuid.uuid4()) + ":" + str(codefin)
                usr.nom = nom
                usr.prenom = prenom
                usr.email = email
                usr.numero_ce = numero_ce
                usr.sexe = sexe
                usr.date_naissance = date_naissance
                usr.cni = cni
                usr.telephone = telephone
                usr.photo=fileurl
                usr.parrain = parrain
                usr.commune = commune
                usr.edition = edition
                usr.departement_org = departement_org
                usr.departement = departement
                usr.region = region
                usr.pays = pays
                usr.sympathisant = sympathisant
                usr.save() 
                data["error"] = False
                data["code"] = 0
                data["data"] = {
                            "id":usr.id,
                            "nom" : usr.nom,
                            "prenom" : usr.prenom,
                            "email" : usr.email,
                            "sexe" : usr.sexe,
                            "date_naissance" : usr.date_naissance,
                            "cni" : usr.cni,
                            "telephone" : usr.telephone,
                            "parrain" : usr.parrain,
                            "commune" : usr.commune,
                            "departement_org" : usr.departement_org,
                            "departement" : usr.departement,
                            "region" : usr.region,
                            "pays" : usr.pays,
                            "sympathisant" : usr.sympathisant,
                            "creation_date" : usr.creation_date,
                            "edition" : usr.edition,
                            }
                status = 200
            except Exception as e :
                data["error"] = True
                data["code"] = -1
                data['description'] = 'Database Writing error occured :' + str(e)
                logger.exception(data["description"])
                status = 300
        elif not form.is_valid():
            status = 400
            data['code'] = -2
            data['error'] = True
            data['description'] = 'Bad datas given '+form.errors.as_text()
            logger.exception(data["description"])
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    
    else:
        status = 400
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method '
        logger.exception(data["description"])
    return JsonResponse(data, status=status)

@csrf_exempt
def updateGarage(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'POST':
        token=request.META['HTTP_AUTHORIZATION']
        payload = json.loads(request.body)
        form = forms.InitGarage(payload)
        #print(token)
        if verifyTokenIn(token=token,request=request) and form.is_valid():
            id = form.cleaned_data["id"]
            nom = form.cleaned_data["nom"]
            prenom = form.cleaned_data["prenom"]
            email = form.cleaned_data["email"]
            sexe = form.cleaned_data["sexe"]
            date_naissance = form.cleaned_data["date_naissance"]
            cni = form.cleaned_data["cni"]
            telephone = form.cleaned_data["telephone"]
            parrain = form.cleaned_data["parrain"]
            commune = form.cleaned_data["commune"]
            departement_org = form.cleaned_data["departement_org"]
            departement = form.cleaned_data["departement"]
            region = form.cleaned_data["region"]
            pays = form.cleaned_data["pays"]
            sympathisant = form.cleaned_data["sympathisant"]
            try:
                usr = Garage.objects.get(id=id)
                usr.nom = nom
                usr.prenom = prenom
                usr.email = email
                usr.sexe = sexe
                usr.date_naissance = date_naissance
                usr.cni = cni
                usr.telephone = telephone
                usr.parrain = parrain
                usr.commune = commune
                usr.departement_org = departement_org
                usr.departement = departement
                usr.region = region
                usr.pays = pays
                usr.sympathisant = sympathisant
                usr.save() 
                data["error"] = False
                data["code"] = 0
                data["data"] = {
                            "id":usr.id,
                            "nom" : usr.nom,
                            "prenom" : usr.prenom,
                            "email" : usr.email,
                            "sexe" : usr.sexe,
                            "date_naissance" : usr.date_naissance,
                            "cni" : usr.cni,
                            "telephone" : usr.telephone,
                            "parrain" : usr.parrain,
                            "commune" : usr.commune,
                            "departement_org" : usr.departement_org,
                            "departement" : usr.departement,
                            "region" : usr.region,
                            "pays" : usr.pays,
                            "sympathisant" : usr.sympathisant,
                            "creation_date" : usr.creation_date,
                            }
                status = 200
            except Exception as e :
                data["error"] = True
                data["code"] = -1
                data['description'] = 'Database Writing error occured :' + str(e)
                status = 300
        elif not form.is_valid():
            status = 400
            data['code'] = -2
            data['error'] = True
            data['description'] = 'Bad datas given '+form.errors.as_text()
            logger.exception(data["description"])
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    else:
        status = 400
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method '
        logger.exception(data["description"])
    return JsonResponse(data, status=status)

@csrf_exempt
def getGarage(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'GET':
        token=request.META['HTTP_AUTHORIZATION']  
        payload = json.dumps(request.GET.dict())
        payload = json.loads(payload)
        print(payload)
        form = forms.getObject(payload)
        if verifyTokenIn(token=token,request=request) and form.is_valid() :
            usr = Garage.objects.get(id=id)
            data["error"] = False
            data["code"] = 0
            data["data"] = {
                    "id":usr.id,
                    "nom" : usr.nom,
                    "email" : usr.email,
                    "telephone1" : usr.telephone1,
                    "telephone2" : usr.telephone2,
                    "photo" : usr.photo,
                    "ville" : usr.ville,
                    "pays" : usr.pays,
                    "longitude" : usr.longitude,
                    "latitude" : usr.latitude,
                    "type" : usr.type,
                    "creation_date" : usr.creation_date,
                    }
            status = 200
        elif not form.is_valid():
                status = 400
                data['code'] = -2
                data['error'] = True
                data['description'] = 'Bad datas given '+form.errors.as_text()
                logger.exception(data["description"])
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    else:
        status = 405
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method'
        logger.exception(data["description"])
    return JsonResponse(data, status=status)

@csrf_exempt
def getGarages(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'GET':
        token=request.META['HTTP_AUTHORIZATION']
        if verifyTokenIn(token=token,request=request) :
            pres = Garage.objects.all()
            res = []
            for usr in pres:
                if usr.id!="":
                    res.append({
                        "id":usr.id,
                        "nom" : usr.nom,
                        "email" : usr.email,
                        "telephone1" : usr.telephone1,
                        "telephone2" : usr.telephone2,
                        "photo" : usr.photo,
                        "ville" : usr.ville,
                        "pays" : usr.pays,
                        "longitude" : usr.longitude,
                        "latitude" : usr.latitude,
                        "type" : usr.type,
                        "creation_date" : usr.creation_date,
                    })
            data["error"] = False
            data["code"] = 0
            data["data"] = res
            status = 200
            logger.info('Garages fetched successfully')
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    else:
        status = 405
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method'
        logger.exception(data["description"])
    return JsonResponse(data, status=status)

@csrf_exempt
def getGaragesAround(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'POST':
        token=request.META['HTTP_AUTHORIZATION']  
        payload = json.loads(request.body)
        form = forms.getGaragesAround(payload)
        if verifyTokenIn(token=token,request=request) and form.is_valid() :
            longitude = form.cleaned_data["longitude"]
            latitude = form.cleaned_data["latitude"]
            key = form.cleaned_data["key"]

            pres = Garage.objects.all()
            result=[]
            userPosition = Point()
            userPosition.lat=latitude
            userPosition.lon=longitude

            for garage in pres:
                garagePosition = Point()
                garagePosition.lat=garage.latitude
                garagePosition.lon=garage.longitude
                
                result.append({
                                "id":garage.id,
                                "nom" : garage.nom,
                                "email" : garage.email,
                                "telephone1" : garage.telephone1,
                                "telephone2" : garage.telephone2,
                                "photo" : garage.photo,
                                "ville" : garage.ville,
                                "description" : garage.description,
                                "pays" : garage.pays,
                                "longitude" : garage.longitude,
                                "distance" : calculateDistance(userPosition,garagePosition),
                                "latitude" : garage.latitude,
                                "type" : garage.type,
                                "creation_date" : garage.creation_date,
                                }) 
            result = sorted(result, key=lambda x: x['distance'])

            data["error"] = False
            data["code"] = 0
            data["data"] = result
            status = 200
        elif not form.is_valid():
                status = 400
                data['code'] = -2
                data['error'] = True
                data['description'] = 'Bad datas given '+form.errors.as_text()
                logger.exception(data["description"])
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    else:
        status = 405
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method'
        logger.exception(data["description"])
    return JsonResponse(data, status=status)

@csrf_exempt
def deleteGarage(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'GET':
        token=request.META['HTTP_AUTHORIZATION']  
        payload = json.dumps(request.GET.dict())
        payload = json.loads(payload)
        print(payload)
        form = forms.getInscription(payload)
        if verifyTokenIn(token=token,request=request) and form.is_valid() :
            Inscription.objects.delete(id=id)
            data["error"] = False
            data["code"] = 0
            data["data"] = id + ' deleted successfully'
            logger.info(data["data"])
            status = 200
        elif not form.is_valid():
            status = 400
            data['code'] = -2
            data['error'] = True
            data['description'] = 'Bad datas given '+form.errors.as_text()
            logger.exception(data["description"])
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    else:
        status = 405
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method'
        logger.exception(data["description"])
    return JsonResponse(data, status=status)




#CRUD views for Discussion Model
@csrf_exempt
def createDiscussion(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'POST':
        token=request.META['HTTP_AUTHORIZATION']
        payload = json.loads(request.body)
        form = forms.InitDiscussion(payload)
        #print(token)
        if verifyTokenIn(token=token,request=request) and form.is_valid():
            id = form.cleaned_data["id"]
            initiateur = form.cleaned_data["initiateur"]
            interlocuteur = form.cleaned_data["interlocuteur"]
            last_message = form.cleaned_data["last_message"]
            last_date = form.cleaned_data["last_date"]
            last_writer = form.cleaned_data["last_writer"]
            try:
                usr = Discussion()
                usr.id=id
                if id=='auto': # or len(id)<10
                    codefin = floor(datetime.datetime.now().timestamp())
                    usr.id = str(uuid.uuid4()) + ":" + str(codefin)
                initiateur=User.objects.get(id=initiateur).id
                interlocuteur=User.objects.get(id=interlocuteur).id
                usr.initiateur = initiateur
                usr.interlocuteur = interlocuteur
                usr.last_message = last_message
                usr.last_date = last_date
                usr.last_writer = last_writer
                usr.save() 
                data["error"] = False
                data["code"] = 0
                data["data"] = {
                            "id":usr.id,
                            "initiateur" : usr.initiateur,
                            "interlocuteur" : usr.interlocuteur,
                            "last_message" : usr.last_message,
                            "last_date" : usr.last_date,
                            "last_writer" : usr.last_writer,
                            "creation_date" : usr.creation_date,
                            }
                status = 200
            except Exception as e :
                data["error"] = True
                data["code"] = -1
                data['description'] = 'Database Writing error occured :' + str(e)
                logger.exception(data["description"])
                status = 300
        elif not form.is_valid():
            status = 400
            data['code'] = -2
            data['error'] = True
            data['description'] = 'Bad datas given '+form.errors.as_text()
            logger.exception(data["description"])
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    else:
        status = 400
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method'
        logger.exception(data["description"])
    return JsonResponse(data, status=status)

@csrf_exempt
def updateDiscussion(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'POST':
        token=request.META['HTTP_AUTHORIZATION']
        payload = json.loads(request.body)
        form = forms.InitDiscussion(payload)
        #print(token)
        if verifyTokenIn(token=token,request=request) and form.is_valid():
            id = form.cleaned_data["id"]
            last_message = form.cleaned_data["last_message"]
            last_date = form.cleaned_data["last_date"]
            last_writer = form.cleaned_data["last_writer"]
            try:
                usr = Discussion.objects.get(id=id)
                usr.last_message = last_message
                usr.last_date = last_date
                usr.last_writer = last_writer
                usr.save() 
                data["error"] = False
                data["code"] = 0
                data["data"] = {
                            "id":usr.id,
                            "initiateur" : usr.initiateur.id,
                            "interlocuteur" : usr.interlocuteur.id,
                            "last_message" : usr.last_message,
                            "last_date" : usr.last_date,
                            "last_writer" : usr.last_writer,
                            "creation_date" : usr.creation_date,
                            }
                status = 200
            except Exception as e :
                data["error"] = True
                data["code"] = -1
                data['description'] = 'Database Writing error occured :' + str(e)
                logger.exception(data["description"])
                status = 300
        elif not form.is_valid():
            status = 400
            data['code'] = -2
            data['error'] = True
            data['description'] = 'Bad datas given '+form.errors.as_text()
            logger.exception(data["description"])
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    else:
        status = 400
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method'
        logger.exception(data["description"])
    return JsonResponse(data, status=status)

@csrf_exempt
def getDiscussion(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'GET':
        token=request.META['HTTP_AUTHORIZATION']  
        payload = json.dumps(request.GET.dict())
        payload = json.loads(payload)
        print(payload)
        form = forms.getObject(payload)
        if verifyTokenIn(token=token,request=request) and form.is_valid() :
            usr = Discussion.objects.get(id=id)
            data["error"] = False
            data["code"] = 0
            data["data"] = {
                            "id":usr.id,
                            "initiateur" : usr.initiateur.id,
                            "interlocuteur" : usr.interlocuteur.id,
                            "last_message" : usr.last_message,
                            "last_date" : usr.last_date,
                            "last_writer" : usr.last_writer,
                            "creation_date" : usr.creation_date,
                    }
            status = 200
        elif not form.is_valid():
                status = 400
                data['code'] = -2
                data['error'] = True
                data['description'] = 'Bad datas given '+form.errors.as_text()
                logger.exception(data["description"])
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    else:
        status = 405
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method'
        logger.exception(data["description"])
    return JsonResponse(data, status=status)

@csrf_exempt
def getDiscussions(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'GET':
        token=request.META['HTTP_AUTHORIZATION']
        if verifyTokenIn(token=token,request=request):
            pres = Discussion.objects.all()
            res = []
            for usr in pres:
                if usr.id!="":
                    res.append({
                            "id":usr.id,
                            "initiateur" : usr.initiateur.id,
                            "interlocuteur" : usr.interlocuteur.id,
                            "last_message" : usr.last_message,
                            "last_date" : usr.last_date,
                            "last_writer" : usr.last_writer,
                            "creation_date" : usr.creation_date,
                    })
            data["error"] = False
            data["code"] = 0
            data["data"] = res
            status = 200
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    else:
        status = 405
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method'
        logger.exception(data["description"])
    return JsonResponse(data, status=status)

@csrf_exempt
def deleteDiscussion(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'GET':
        token=request.META['HTTP_AUTHORIZATION']  
        payload = json.dumps(request.GET.dict())
        payload = json.loads(payload)
        print(payload)
        form = forms.getObject(payload)
        if verifyTokenIn(token=token,request=request) and form.is_valid() :
            id = form.cleaned_data["id"]
            Discussion.objects.delete(id=id)
            data["error"] = False
            data["code"] = 0
            data["data"] = id + ' deleted successfully'
            logger.info(data["data"])
            status = 200
        elif not form.is_valid():
                status = 400
                data['code'] = -2
                data['error'] = True
                data['description'] = 'Bad datas given '+form.errors.as_text()
                logger.exception(data["description"])
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    else:
        status = 405
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method'
        logger.exception(data["description"])
    return JsonResponse(data, status=status)



#CRUD views for Message Model
@csrf_exempt
def createMessage(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'POST':
        token=request.META['HTTP_AUTHORIZATION']
        payload = json.loads(request.body)
        
        form = forms.InitMessage(payload)
        if verifyTokenIn(token=token,request=request) and form.is_valid():
            discussion = form.cleaned_data["discussion"]
            emetteur = form.cleaned_data["emetteur"]
            media = form.cleaned_data["media"]
            contenu = form.cleaned_data["contenu"]
            answerTo = form.cleaned_data["answerTo"]
            date_envoi = form.cleaned_data["date_envoi"]
            try:
                usr = Message()
                usr.id=id
                if id=='auto':
                    codefin = floor(datetime.datetime.now().timestamp())
                    usr.id = str(uuid.uuid4()) + ":" + str(codefin)
                
                disc = Discussion.objects.get(id=discussion)
                disc.last_message = contenu
                disc.last_writer = User.objects.get(id=emetteur)
                disc.last_date = usr.date_envoi
                disc.save()

                usr.media = media
                usr.contenu = contenu
                usr.emetteur = User.objects.get(id=emetteur)
                usr.discussion = disc
                usr.answerTo = answerTo
                if date_envoi != 0:
                    usr.date_envoi = date_envoi
                usr.save() 


                data["error"] = False
                data["code"] = 0
                data["data"] = {
                            "id":usr.id,
                            "disc_id" : usr.discussion.id,
                            "emetteur" : usr.emetteur,
                            "contenu" : usr.contenu,
                            "media" : usr.media,
                            "answerTo" : usr.answerTo,
                            "date_envoi" : usr.date_envoi,
                            "creation_date" : usr.creation_date,
                            }
                status = 200
            except Exception as e :
                data["error"] = True
                data["code"] = -1
                data['description'] = 'Database Writing error occured :' + str(e)
                logger.exception(data["description"])
                status = 300
        elif not form.is_valid():
            status = 400
            data['code'] = -2
            data['error'] = True
            data['description'] = 'Bad datas given '+form.errors.as_text()
            logger.exception(data["description"])
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    else:
        status = 400
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method'
        logger.exception(data["description"])
    return JsonResponse(data, status=status)

@csrf_exempt
def getMessage(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'GET':
        token=request.META['HTTP_AUTHORIZATION']  
        payload = json.dumps(request.GET.dict())
        payload = json.loads(payload)
        print(payload)
        form = forms.getObject(payload)
        if verifyTokenIn(token=token,request=request) and form.is_valid() :
            id=form.cleaned_data['id']
            user_id=form.cleaned_data['user_id']
            usr = Message.objects.get(id=id)
            data["error"] = False
            data["code"] = 0
            data["data"] = {
                            "id":usr.id,
                            "disc_id" : usr.discussion.id,
                            "emetteur" : usr.emetteur,
                            "contenu" : usr.contenu,
                            "media" : usr.media,
                            "answerTo" : usr.answerTo,
                            "date_envoi" : usr.date_envoi,
                            "creation_date" : usr.creation_date,
                    }
            status = 200
        elif not form.is_valid():
                status = 400
                data['code'] = -2
                data['error'] = True
                data['description'] = 'Bad datas given '+form.errors.as_text()
                logger.exception(data["description"])
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    else:
        status = 405
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method'
        logger.exception(data["description"])
    return JsonResponse(data, status=status)

@csrf_exempt
def getMessages(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'GET':
        token=request.META['HTTP_AUTHORIZATION']
        if verifyTokenIn(token=token,request=request):
            pres = Message.objects.all()
            res = []
            for usr in pres:
                if usr.id!="":
                    emetteurName='System'
                    emetteur=User.objects.filter(id=usr.emetteur)
                    if len(emetteur)>0:
                        emetteur=emetteur[0]
                        emetteurName=emetteur.nom+' '+emetteur.prenom
                
                    res.append({
                            "id":usr.id,
                            "disc_id" : usr.discussion.id,
                            "emetteur" : usr.emetteur,
                            "contenu" : usr.contenu,
                            "media" : usr.media,
                            "answerTo" : usr.answerTo,
                            "date_envoi" : usr.date_envoi,
                            "creation_date" : usr.creation_date,
                    })
            data["error"] = False
            data["code"] = 0
            data["data"] = res
            status = 200
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    else:
        status = 405
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method'
        logger.exception(data["description"])
    return JsonResponse(data, status=status)

@csrf_exempt
def deleteMessage(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'GET':
        token=request.META['HTTP_AUTHORIZATION']  
        payload = json.dumps(request.GET.dict())
        payload = json.loads(payload)
        print(payload)
        form = forms.getObject(payload)
        if verifyTokenIn(token=token,request=request) and form.is_valid() :
            Message.objects.delete(id=id)
            data["error"] = False
            data["code"] = 0
            data["data"] = id + ' deleted successfully'
            logger.info(data["data"])
            status = 200
        elif not form.is_valid():
                status = 400
                data['code'] = -2
                data['error'] = True
                data['description'] = 'Bad datas given '+form.errors.as_text()
                logger.exception(data["description"])
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    else:
        status = 405
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method'
        logger.exception(data["description"])
    return JsonResponse(data, status=status)

@csrf_exempt
def getMessagesFromDisc(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'GET':
        token=request.META['HTTP_AUTHORIZATION']  
        payload = json.dumps(request.GET.dict())
        payload = json.loads(payload)
        print(payload)
        form = forms.getMessage(payload)
        if verifyTokenIn(token=token,request=request) and form.is_valid() :
            disc_id=form.cleaned_data['id']
            time=form.cleaned_data['time']
            if not time:
                time=0
            pres = Message.objects.filter(disc_id=disc_id)
            res = []
            for usr in pres:
                if usr.id!="" and usr.creation_date >= time:
                    res.append({
                            "id":usr.id,
                            "disc_id" : usr.discussion.id,
                            "emetteur" : usr.emetteur,
                            "contenu" : usr.contenu,
                            "media" : usr.media,
                            "answerTo" : usr.answerTo,
                            "date_envoi" : usr.date_envoi,
                            "creation_date" : usr.creation_date,
                    })
            data["error"] = False
            data["code"] = 0
            data["data"] = res
            status = 200
        elif not form.is_valid():
                status = 400
                data['code'] = -2
                data['error'] = True
                data['description'] = 'Bad datas given '+form.errors.as_text()
                logger.exception(data["description"])
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    else:
        status = 405
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method'
        logger.exception(data["description"])
    return JsonResponse(data, status=status)

@csrf_exempt
def getDiscusionsFromUser(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'GET':
        token=request.META['HTTP_AUTHORIZATION']  
        payload = json.dumps(request.GET.dict())
        payload = json.loads(payload)
        #print(payload)
        form = forms.getObject(payload)
        if verifyTokenIn(token=token,request=request) and form.is_valid() :
            user_id=form.cleaned_data['id']
            user=User.objects.filter(id=user_id)
            if len(user)>0:
                user=user[0]
                res = []
                discs = Discussion.objects.filter(initiateur=user_id) | Discussion.objects.filter(interlocuteur=user_id)
                #print(discs)
                for usr in discs:
                    if usr.id!="":
                        res.append({
                                "id":usr.id,
                                "initiateur" : usr.initiateur,
                                "interlocuteur" : usr.interlocuteur,
                                "last_message" : usr.last_message,
                                "last_date" : usr.last_date,
                                "last_writer" : usr.last_writer,
                                "creation_date" : usr.creation_date
                            })  
                data["error"] = False
                data["code"] = 0
                data["data"] = res
                status = 200
            else:
                status = 400
                data['code'] = -1
                data['error'] = True
                data['description'] = 'User doesn\'t exist'
                logger.exception(data["description"])
        elif not form.is_valid():
                status = 400
                data['code'] = -2
                data['error'] = True
                data['description'] = 'Bad datas given '+form.errors.as_text()
                logger.exception(data["description"])
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    else:
        status = 405
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method'
        logger.exception(data["description"])
    return JsonResponse(data, status=status)



#files management
def save_file(request_file,ext):
    fs = FileSystemStorage()
    file = fs.save('files/'+token_hex(8)+'_'+str(int(datetime.datetime.now().timestamp()))
                    +'.'+ext, request_file)
    # the fileurl variable now contains the url to the file. This can be used to serve the file when needed.
    fileurl = fs.url(file)
    return fileurl

def save_image(request_file,ext):
    fs = FileSystemStorage()
    file = fs.save('images/'+token_hex(8)+'_'+str(int(datetime.datetime.now().timestamp()))
                    +'.'+ext, request_file)
    # the fileurl variable now contains the url to the file. This can be used to serve the file when needed.
    fileurl = fs.url(file)
    return fileurl

@csrf_exempt
def upload_file(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'POST':
        token=request.META['HTTP_AUTHORIZATION']
        # if the PUT request has a file under the input name 'document', then save the file.
        request_file = request.FILES['document'] if 'document' in request.FILES else None
        if verifyTokenIn(token=token,request=request) and request_file:
            fileurl = save_file(request_file,request.POST.get("ext",'pdf'))
            status=200
            data['code'] = 0
            data['error'] = False
            data["data"] = {
                            "fileurl":fileurl
                            }
            logger.exception(data["data"])
        elif not request_file:
            status = 400
            data['code'] = -2
            data['error'] = True
            data['description'] = 'No file found in request'
            logger.exception(data["description"])
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    return JsonResponse(data, status=status)

@csrf_exempt
def upload_image(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'POST':
        token=request.META['HTTP_AUTHORIZATION']
        # if the PUT request has a file under the input name 'document', then save the file.
        request_file = request.FILES['image'] if 'image' in request.FILES else None
        print(request.POST.get("ext",'jpg'))
        
        if verifyTokenIn(token=token,request=request) and request_file:
            fileurl = save_image(request_file,request.POST.get("ext",'jpg'))
            status=200
            data['code'] = 0
            data['error'] = False
            data["data"] = {
                            "fileurl":fileurl
                            }
            logger.exception(data["data"])
        elif not request_file:
            status = 400
            data['code'] = -2
            data['error'] = True
            data['description'] = 'No file found in request'
            logger.exception(data["description"])
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    return JsonResponse(data, status=status)


def AIRrequest(message:Message,discussion:Discussion):
    answer = "Salut "+message.emetteur.prenom +", je m'appelle MUNTUR AI, je suis à ton écoute."
    return answer

from nltk.corpus import movie_reviews
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
import string
from django.conf import settings

def preprocess_text(text):
    # Tokenize the text into individual words
    tokens = word_tokenize(text.lower())
    # Remove stopwords and punctuation
    stop_words = set(stopwords.words('english') + list(string.punctuation))
    filtered_tokens = [token for token in tokens if token not in stop_words]
    # Return the filtered tokens as a string
    return ' '.join(filtered_tokens)

# Define a function to generate a chatbot response
def generate_response_car_preloaded(user_input):
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.feature_extraction.text import CountVectorizer
    import pickle
    # Preprocess and tokenize the user inputimport pickle
    f = open(settings.MEDIA_ROOT+'/models/car_classifier.pickle', 'rb')
    classifier = pickle.load(f)
    f.close()
    f = open(settings.MEDIA_ROOT+'/models/car_vectorizer.pickle', 'rb')
    vectorizer = pickle.load(f)
    f.close()
    preprocessed_input = preprocess_text(user_input)
    input_vector = vectorizer.transform([preprocessed_input])
    predicted_category = classifier.predict(input_vector)[0]
    
    return predicted_category

#Special Views
@csrf_exempt
def askQuestion(request):
    data = {
        "error": True,
        "code": -4,
    }
    status = 400
    if request.method == 'POST':
        token=request.META['HTTP_AUTHORIZATION']
        payload = json.loads(request.body)
        
        form = forms.InitMessage(payload)
        if verifyTokenIn(token=token,request=request) and form.is_valid():
            discussion = form.cleaned_data["discussion"]
            emetteur = form.cleaned_data["emetteur"]
            media = form.cleaned_data["media"]
            contenu = form.cleaned_data["contenu"]
            date_envoi = form.cleaned_data["date_envoi"]
            try:
                usr = Message()
                codefin = floor(datetime.datetime.now().timestamp())
                usr.id = str(uuid.uuid4()) + ":" + str(codefin)
                
                discs = Discussion.objects.filter(id=discussion)
                if(len(discs)==0):
                    disc=Discussion()
                    disc.id=discussion
                    disc.initiateur = User.objects.get(id=emetteur)
                    disc.interlocuteur = User.objects.get(id='1')
                    disc.last_message = contenu
                    disc.last_writer = emetteur
                    disc.last_date = date_envoi
                    disc.save()
                    
                else:
                    disc=discs[0]

                usr.media = media
                usr.contenu = contenu
                usr.emetteur = User.objects.get(id=emetteur)
                usr.discussion = disc
                usr.date_envoi = date_envoi
                usr.save() 

                AiResponse = Message()
                codefin = floor(datetime.datetime.now().timestamp())
                AiResponse.id = str(uuid.uuid4()) + ":" + str(codefin)
                AiResponse.contenu = generate_response_car_preloaded(contenu)
                AiResponse.emetteur = User.objects.get(id='1')
                AiResponse.discussion = disc
                AiResponse.date_envoi = date_envoi
                AiResponse.save()

                disc.last_message = AiResponse.contenu
                disc.last_writer = AiResponse.emetteur.id
                disc.last_date = date_envoi
                disc.save()

                data["error"] = False
                data["code"] = 0
                data["data"] = {
                            "id":AiResponse.id,
                            "disc_id" : AiResponse.discussion.id,
                            "emetteur" : AiResponse.emetteur.id,
                            "contenu" : AiResponse.contenu,
                            "media" : AiResponse.media,
                            "date_envoi" : AiResponse.date_envoi,
                            "creation_date" : AiResponse.creation_date,
                            }
                status = 200
            except Exception as e :
                data["error"] = True
                data["code"] = -1
                data['description'] = 'Database Writing error occured :' + str(e)
                logger.exception(data["description"])
                status = 300
        elif not form.is_valid():
            status = 400
            data['code'] = -2
            data['error'] = True
            data['description'] = 'Bad datas given '+form.errors.as_text()
            logger.exception(data["description"])
        else:
            status = 400
            data['code'] = -3
            data['error'] = True
            data['description'] = 'Bad Authorization'
            logger.exception(data["description"])
    else:
        status = 400
        data['code'] = -4
        data['error'] = True
        data['description'] = 'Unauthorized method'
        logger.exception(data["description"])
    return JsonResponse(data, status=status)

