## Installation
- Telecharger et installer Python 3.12 
- Ouvrir le repertoire de l'API avec VS code 
- ouvrir le terminal VS code
- executer "python -m venv muntur-env" dans la console
- executer ".\muntur-env\Scripts\activate" 
- executer "pip install -r requirements.txt" et patienter   jusqu'à la fin de l'installation
## Creation du compte superAdmin
- executer "python manage.py createsuperuser" et suivre les etapes de creation de compte super utilisateur 
NB: veuiller noter les coordonnees de connexion du compte créé quelque part en securité
## Lancement du serveur
- Executer "python manage.py runserver"

## Lancement du serveur sur reseau public
- detecter l'addresse IP de votre Machine qu'on appellera ADDRESSE_IP
- Executer "python manage.py runserver ADDRESSE_IP:8000" et tester la connexion avec l'Application
- C'est tout !
