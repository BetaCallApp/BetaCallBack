from django.contrib import admin
from .models import User, Profile

# Register your models here.


class UserAdmin(admin.ModelAdmin):

    list_display = ['email', ]


class ProfileAdmin(admin.ModelAdmin):

    list_display = ['user', 'full_name', ]


admin.site.register(User, UserAdmin)
admin.site.register(Profile, ProfileAdmin)
