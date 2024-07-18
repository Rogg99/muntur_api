from django import forms
from . import constances as c 


class InitToken(forms.Form):
    id = forms.CharField(required=True)
    email = forms.CharField(required=True)
    password = forms.CharField(required=True)

    def __init__(self, *args, **kwargs):
        super(InitToken, self).__init__(*args, **kwargs)

    def clean(self):
        return self.cleaned_data

class getToken(forms.Form):
    email = forms.CharField(required=True)
    password = forms.CharField(required=True)

    def __init__(self, *args, **kwargs):
        super(getToken, self).__init__(*args, **kwargs)

    def clean(self):
        return self.cleaned_data

class verifytoken(forms.Form):
    access = forms.CharField(required=True)

    def __init__(self, *args, **kwargs):
        super(verifytoken, self).__init__(*args, **kwargs)

    def clean(self):
        return self.cleaned_data
    

class InitUser(forms.Form):
    id = forms.CharField(required=True)
    nom = forms.CharField(required=True)
    prenom = forms.CharField(required=True)
    email = forms.CharField(required=True)
    password = forms.CharField(required=True)
    photo = forms.CharField(required=True)
    sexe = forms.CharField(required=True)
    date_naissance = forms.IntegerField(required=True)
    type = forms.CharField(required=True)
    cni = forms.CharField(required=True)
    telephone = forms.CharField(required=True)
    parti = forms.CharField(required=True)                                                              
    matricule = forms.CharField(required=True)
    parrain = forms.CharField(required=True)
    commune = forms.CharField(required=True)
    departement_org = forms.CharField(required=True)
    departement = forms.CharField(required=True)
    region = forms.CharField(required=True)
    pays = forms.CharField(required=True)
    preinscrit= forms.BooleanField(required=False)
    inscrit= forms.BooleanField(required=False)
    sympathisant = forms.CharField(required=True)

    def __init__(self, *args, **kwargs):
        super(InitUser, self).__init__(*args, **kwargs)

    def clean(self):
        return self.cleaned_data

class getUserwithemail(forms.Form):
    email = forms.CharField(required=True)

    def __init__(self, *args, **kwargs):
        super(getUserwithemail, self).__init__(*args, **kwargs)

    def clean(self):
        return self.cleaned_data


class SettUserPasword(forms.Form):
    oldpassword = forms.CharField(required=True)
    newpassword = forms.CharField(required=True)

    def __init__(self, *args, **kwargs):
        super(SettUserPasword, self).__init__(*args, **kwargs)

    def clean(self):
        return self.cleaned_data

class setUserphoto(forms.Form):
    id = forms.CharField(required=True)
    photo = forms.CharField(required=True)

    def __init__(self, *args, **kwargs):
        super(setUserphoto, self).__init__(*args, **kwargs)

    def clean(self):
        return self.cleaned_data

class getGaragesAround(forms.Form):
    latitude = forms.FloatField(required=True)
    longitude = forms.FloatField(required=True)

    def __init__(self, *args, **kwargs):
        super(getGaragesAround, self).__init__(*args, **kwargs)

    def clean(self):
        return self.cleaned_data


class getObject(forms.Form):
    id = forms.CharField(required=True)

    def __init__(self, *args, **kwargs):
        super(getObject, self).__init__(*args, **kwargs)

    def clean(self):
        return self.cleaned_data

class InitGarage(forms.Form):
    id = forms.CharField(required=False)
    nom = forms.CharField(required=True)
    description = forms.CharField(required=True)
    email = forms.CharField(required=True)
    photo = forms.CharField(required=True)
    telephone1 = forms.CharField(required=True)
    telephone2 = forms.CharField(required=False)
    type = forms.CharField(required=True)
    latitude = forms.FloatField(required=True)
    longitude = forms.FloatField(required=True)
    ville = forms.CharField(required=True)
    pays = forms.CharField(required=True)

    def __init__(self, *args, **kwargs):
        super(InitGarage, self).__init__(*args, **kwargs)

    def clean(self):
        return self.cleaned_data

class InitDiscussion(forms.Form):
    id = forms.CharField(required=False)
    initiateur = forms.CharField(required=True)
    interlocuteur = forms.CharField(required=True)
    title = forms.CharField(required=True)
    type = forms.CharField(required=True)
    last_message = forms.CharField(max_length=10000)
    last_message_statut = forms.CharField(max_length=100)
    last_date = forms.IntegerField(max_value=None)
    last_writer = forms.CharField(max_length=100)

    def __init__(self, *args, **kwargs):
        super(InitDiscussion, self).__init__(*args, **kwargs)

    def clean(self):
        return self.cleaned_data

class InitInfo(forms.Form):
    id = forms.CharField(required=False)
    image = forms.CharField(required=True)
    title = forms.CharField(required=True)
    path = forms.CharField(required=True)
    time = forms.IntegerField(max_value=None)

    def __init__(self, *args, **kwargs):
        super(InitInfo, self).__init__(*args, **kwargs)

    def clean(self):
        return self.cleaned_data

class InitMessage(forms.Form):
    id = forms.CharField(required=False)
    discussion = forms.CharField(required=True)
    emetteur = forms.CharField(required=True)
    media = forms.CharField(required=False)
    mediaName = forms.CharField(required=False)
    mediaSize = forms.CharField(required=False)
    contenu = forms.CharField(max_length=10000,required=True)
    date_envoi = forms.IntegerField(required=True)

    def __init__(self, *args, **kwargs):
        super(InitMessage, self).__init__(*args, **kwargs)

    def clean(self):
        return self.cleaned_data


