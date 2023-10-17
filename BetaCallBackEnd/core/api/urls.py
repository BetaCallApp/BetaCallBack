from django.urls import path
from . import views

urlpatterns = [

    # User
    path('login', views.LoginView.as_view()),
    path('signup', views.RegisterView.as_view()),
    path('user', views.UserView.as_view()),
    path('logout', views.LogoutView.as_view()),
    path('confirm/<str:token>/', views.ConfirmAccountView.as_view()),

    # Profile
    path('my-profile/', views.ProfileView.as_view(), name='detail'),
    path('my-profile-edit/', views.ProfileView.as_view(), name='edit'),


    # Chat Messaging Func
    path('chat/', views.MyInbox.as_view()),
    path('chat/<int:sender>/<int:receiver>/', views.GetMessage.as_view()),
    path('messages/<int:sender>/<int:receiver>/', views.MessageList.as_view()),
    path('messages/', views.MessageList.as_view()),
]
