from django.contrib import admin
from .models import *


admin.site.site_title = "MUNTUR AI"
admin.site.site_header = "MUNTUR AI administration"
admin.site.index_title = "Site administration"

admin.site.register(User)
admin.site.register(Discussion)
admin.site.register(Message)
admin.site.register(Token)
admin.site.register(Garage)

# Register your models here.
