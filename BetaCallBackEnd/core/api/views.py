from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import status, generics, permissions
from rest_framework.views import APIView

from django.core.mail import send_mail
from django.conf import settings

from rest_framework.permissions import IsAuthenticated

from .models import Profile, User, Message

import jwt
import datetime

from django.db.models import Q
from django.core import signing


from .serializers import UserSerializer, MessageSerializer, ProfileSerializer


class DashbordView(APIView):
    def get(self, request):
        pass


class MyInbox(generics.ListAPIView):
    serializer_class = MessageSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        queryset = Message.objects.filter(sender=user) | Message.objects.filter(receiver=user)
        conversations = {}
        for message in queryset:
            other_user = message.receiver if message.sender == user else message.sender
            if other_user in conversations:
                conversations[other_user].append(message)
            else:
                conversations[other_user] = [message]
        return conversations


class MessageList(APIView):
    def get(request, sender=None, receiver=None):
        messages = Message.objects.filter(
            sender_id=sender, receiver_id=receiver, is_read=False)
        serializer = MessageSerializer(
            messages, many=True, context={'request': request})
        for message in messages:
            message.is_read = True
            message.save()
        return Response({
            "serializer": serializer.data
        }, safe=False)

    def post(request):
        serializer = MessageSerializer(data=request)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "serializer": serializer.data
            }, status.HTTP_201_CREATED)
        return Response({
            "serializer": serializer.errors
        }, status.HTTP_400_BAD_REQUEST)


class GetMessage(APIView):
    def get(self, request, sender, receiver):
        if not request.user.is_authenticated:
            return IsAuthenticated("Unauthorized!")
        return Response(
                      {'users': User.objects.exclude(email=request.user.email),
                       'receiver': User.objects.get(id=receiver),
                       'messages': Message.objects.filter(sender_id=sender, receiver_id=receiver) |
                                   Message.objects.filter(sender_id=receiver, receiver_id=sender)})


class SearchUser(generics.ListAPIView):
    serializer_class = ProfileSerializer
    queryset = Profile.objects.all()
    permission_classes = [IsAuthenticated] 

    def list(self, request, *args, **kwargs):
        email = self.kwargs['email']
        logged_in_user = self.request.user
        users = Profile.objects.filter(Q(user__email__icontains=email) |
                                       Q(full_name__icontains=email) |
                                         Q(user__email__icontains=email) &
                                       ~Q(user=logged_in_user))

        if not users.exists():
            return Response(
                {"detail": "No users found."},
                status=status.HTTP_404_NOT_FOUND
            )

        serializer = self.get_serializer(users, many=True)
        return Response(serializer.data)



secret_key = 'CJWwVX6HTsYp3rGaUeKbkN11tm4P8E9Z7AMQBFqDcxnfjLh25RCJWwVX6HTsYp3rGa'


class RegisterView(APIView):
    def post(self, request):
        user_serializer = UserSerializer(data=request.data)
        user_serializer.is_valid(raise_exception=True)
        user = user_serializer.save()

        # Create the profile for the user
        Profile.objects.create(user=user, full_name=f"{user.first_name} {user.last_name}")

        confirmation_token = signing.dumps({'user_id': user.id})

        token_url = f'http://127.0.0.1:8000/api/confirm/{confirmation_token}/'
        subject = 'Confirm Your Account'
        message = f'Click the following link to confirm your account: {token_url}'
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [user.email]

        send_mail(subject, message, from_email, recipient_list, fail_silently=False)

        return Response(user_serializer.data, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = User.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed('User not found')

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password!')

        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }

        # token = jwt.encode(payload, 'secret', algorithm='HS256')
        #                          .decode('utf-8')
        token = jwt.encode(payload, secret_key, algorithm='HS256')

        response = Response()

        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            "jwt": token
        }

        return response


class ProfileView(APIView):
    def get(self, request):

        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

        profile = Profile.objects.first()
        serializer = ProfileSerializer(profile)

        return Response(serializer.data)

    def put(self, request):
        profile_serializer = UserSerializer(data=request.data)
        profile_serializer.is_valid(raise_exception=True)
        profile = profile_serializer.save()

        profile = self.request.user.profile
        serializer = self.get_serializer(profile, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserView(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

        user = User.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)
        return Response(serializer.data)


class ConfirmAccountView(APIView):
    def get(self, request, token):
        try:
            data = signing.loads(token)
            user_id = data['user_id']
            user = User.objects.get(pk=user_id)
            user.is_active = True
            user.save()
            return Response({'message': 'Account confirmed successfully'},
                            status=status.HTTP_200_OK)
        except signing.BadSignature:
            return Response({'error': 'Invalid or expired token'},
                            status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            "message": "success"
        }
        return response
