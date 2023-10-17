from django.db import models
from django.contrib.auth.models import AbstractUser

# User


class User(AbstractUser):
    email = models.EmailField(max_length=255, unique=True)
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    verified = models.BooleanField(default=False)
    username = None

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def profile(self):
        profile = Profile.objects.get(user=self)

    def __str__(self):
        return self.email


# Profile

class Profile(models.Model):

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    full_name = models.CharField(max_length=200)
    image = models.ImageField(upload_to="user_images", default="default.png")
    phone = models.CharField(max_length=50, null=True)
    address = models.CharField(max_length=255, null=True)
    language = models.CharField(max_length=50, null=True)
    link = models.CharField(max_length=1000, null=True)
    role = models.CharField(max_length=255, null=True)

# Chat Model


class Message(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sender')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='receiver')
    message = models.CharField(max_length=1200)
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return self.message

    class Meta:
        ordering = ('timestamp',)
