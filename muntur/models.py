from django.db import models
from math import floor
import datetime, uuid
from django.utils import timezone


# Create your models here.
class Token(models.Model):
    id = models.CharField(max_length=100,primary_key=True)
    email = models.CharField(max_length=100,null=False)
    password = models.CharField(max_length=100,null=False)
    now=floor(datetime.datetime.now().timestamp())
    creation_date = models.IntegerField(default=now)
    
    class Meta:
        ordering =["creation_date"]

    def __str__(self):
        return self.id
       
class Session(models.Model):
    id = models.CharField(max_length=100,primary_key=True)
    email = models.CharField(max_length=200)
    access = models.CharField(max_length=300,default='')
    refresh = models.CharField(max_length=300,default='')
    ip = models.CharField(max_length=1000,default='')
    now=floor(datetime.datetime.now().timestamp())
    end_time = models.IntegerField(default=(now + (3600*24*30)))
    creation_date = models.IntegerField(default=now)
    
    class Meta:
        ordering =["creation_date"]

    def __str__(self):
        return self.id

class User(models.Model):
    id = models.CharField(primary_key=True,unique=True,max_length=100)
    nom = models.CharField(max_length=100,default='')
    prenom = models.CharField(max_length=100,default='')
    email = models.CharField(max_length=100,unique=True)
    photo = models.CharField(max_length=200,default='')
    sexe = models.CharField(max_length=100)
    date_naissance = models.IntegerField(default=0)
    type = models.CharField(max_length=200,default='user')
    telephone = models.CharField(max_length=200)
    ville = models.CharField(max_length=200,null=False)
    pays = models.CharField(max_length=200,default='CAMEROUN')
    now=floor(datetime.datetime.now().timestamp())
    creation_date = models.IntegerField(default=now)
    
    class Meta:
        ordering =["creation_date"]

    def __str__(self):
        return self.nom +' '+ self.prenom


class Garage(models.Model):
    id = models.CharField(primary_key=True,unique=True,max_length=100)
    nom = models.CharField(max_length=100,null=False)
    description = models.CharField(max_length=100,default='')
    email = models.CharField(max_length=100,unique=True,null=False)
    telephone1 = models.CharField(max_length = 200,null=False)
    telephone2 = models.CharField(max_length = 200)
    photo = models.CharField(max_length = 200)
    ville = models.CharField(max_length = 100,null=False)
    pays = models.CharField(max_length = 200,default='CAMEROUN')
    longitude = models.FloatField(null=False)
    latitude = models.FloatField(null=False)
    type = models.CharField(max_length=200,default='garage') # garage, parking, centre de visite,...
    now=floor(datetime.datetime.now().timestamp())
    creation_date = models.IntegerField(default=now)
    
    class Meta:
        ordering =["creation_date"]

    def __str__(self):
        return self.nom +' '+ self.ville

class Rate(models.Model):
    id = models.CharField(primary_key=True,unique=True,max_length=100)
    user = models.CharField(max_length=100,null=False)
    garage = models.CharField(max_length=100,null=False)
    rate = models.IntegerField(default=0)
    comment = models.CharField(max_length=100)
    now=floor(datetime.datetime.now().timestamp())
    creation_date = models.IntegerField(default=now)
    
    class Meta:
        ordering =["creation_date"]

    def __str__(self):
        return self.nom +' '+ self.ville


class Discussion(models.Model):
    id = models.CharField(primary_key=True,unique=True,max_length=100)
    initiateur = models.ForeignKey(User,on_delete=models.DO_NOTHING,related_name='emeteur')
    interlocuteur = models.ForeignKey(User,on_delete=models.DO_NOTHING,related_name='interlocuteur')
    last_message = models.CharField(max_length=10000)
    last_date = models.IntegerField(null=False)
    last_writer = models.CharField(max_length=100)
    last_message_statut = models.CharField(max_length=100,default='sent')
    now=floor(datetime.datetime.now().timestamp())
    creation_date = models.IntegerField(default=now)
    
    class Meta:
        ordering =["creation_date"]

    def __str__(self):
        return 'Discussion : '+ str(self.initiateur) +' >> '+ str(self.interlocuteur)

class Message(models.Model):
    id = models.CharField(primary_key=True,unique=True,max_length=100)
    discussion = models.ForeignKey(Discussion, on_delete=models.CASCADE)
    emetteur = models.ForeignKey(User, on_delete=models.CASCADE)
    contenu = models.CharField(max_length=10000)
    media = models.CharField(max_length=200,default='none')
    answerTo = models.CharField(max_length=200,default='none')
    now=floor(datetime.datetime.now().timestamp())
    date_envoi = models.IntegerField(default=now)
    creation_date = models.IntegerField(default=now)
    
    class Meta:
        ordering =["creation_date"]

    def __str__(self):
        return str(self.emetteur) +' : '+ self.contenu