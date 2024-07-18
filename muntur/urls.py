from django.urls import path
from . import views
from django.conf.urls.static import static
from django.conf import settings



urlpatterns = [
    path("", views.welcomePage, name="Home"),
    
    path("user/token/add", views.createToken, name="create-user-token"),
    path("token", views.refreshToken, name="login"),
    path("token/setpassword", views.setPassword, name="setpassword"),
    path("token/logout", views.signOut, name="logout"),
    path("token/verify", views.verifyToken, name="verify-token"),
    
    
    path("user/add", views.createUser, name="add-user"),
    path("user/set", views.updateUser, name="set-user"),
    path("user/get", views.getUser, name="get-user"),
    path("user/getwithemail", views.getUserWithEmailandPwd, name="get-userwithemail"),
    path("user/delete", views.deleteUser, name="delete-user"),
    
    path("garage/add", views.createGarage, name="add-garage"),
    path("garage/set", views.updateGarage, name="set-garage"),
    path("garage/get", views.getGarage, name="get-garage"),
    path("garages/get", views.getGarages, name="get-garages"),
    path("garages/around/get", views.getGaragesAround, name="get-garages-around"),
    path("garage/delete", views.deleteGarage, name="delete-garage"),

    path("discussion/add", views.createDiscussion, name="add-discussion"),
    path("discussion/set", views.updateDiscussion, name="set-discussion"),
    path("discussion/get", views.getDiscussion, name="get-discussion"),
    path("discussions/get", views.getDiscussions, name="get-discussions"),
    path("discussions/user/get", views.getDiscusionsFromUser, name="get-discussions-from-user"),
    path("discussion/delete", views.deleteDiscussion, name="delete-discussion"),

    path("request", views.askQuestion, name="send-request"),
    path("message/add", views.createMessage, name="add-message"),
    path("message/get", views.getMessage, name="get-message"),
    path("messages/get", views.getMessages, name="get-messages"),
    path("messages/discussion/get", views.getMessagesFromDisc, name="get-messages"),
    path("message/delete", views.deleteMessage, name="delete-message"),

]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root = settings.MEDIA_ROOT)
