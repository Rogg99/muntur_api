import requests
import json
from ..models import Token

User_END_POINT = "http://192.168.1.137:2000/users/account/"

STATUT_VALIDATION_CHOICE = [
    ('1', 'waiting_for_response'),
    ('2', 'acccepted'),
    ('3', 'rejected'),
    ('4', 'deleted'),
    ('5', 'suspended'),
]


def verifyTokenSuperUser(token: str):
    tokens = Token.objects.filter(access=token)
    
    if (len(tokens) == 0 or (tokens[0].email.lower().find('system')==-1 and tokens[0].email.lower().find('admin') == -1)) :
        return False
    return True


def verifyToken(token: str):
    tokens = Token.objects.filter(access=token)
    if len(tokens)== 0:
        return False
    return True

def verifyTokenSuperUser2(token: str):
    url = User_END_POINT
    res = requests.get(url=url,headers={"Authorization": token})
    _profil=json.loads(res.text)
    if(res.status_code==200 and _profil['member']['is_superuser']==True):
        return True
    return False

def verifyToken2(token: str):
    url = User_END_POINT
    res = requests.get(url=url,headers={"Authorization": token})
    if(res.status_code!=200):
        return False
    return True

def verifyToken2(token: str):
    return True

