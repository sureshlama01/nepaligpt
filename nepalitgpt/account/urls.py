from django.urls import path
from .views import UserRegistrationView,UserLoginView,UserProfileView,ChangePasswordView,PasswordResetView,PasswordResetConfirm


urlpatterns = [
    path('register/',UserRegistrationView.as_view(),name='register'),\
    path('login/',UserLoginView.as_view(),name='login'),
    path('profile/',UserProfileView.as_view(),name='profile'),
    path('change-password/',ChangePasswordView.as_view({'put':'update'}),name='change-password'),
    path('password-reset/',PasswordResetView.as_view({'post':'create'}),name='password-reset'),
    path('password-reset/<str:encoded_pk>/<str:token>/',PasswordResetConfirm.as_view({'patch':'partial_update'}),name='password-reset'),
]
