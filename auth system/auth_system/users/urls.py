from django.urls import path

from .views import (
    signup,
    signin,
    logout_success,
    profilePage,
    change_the_pass,
    reset_the_pass,
    confirm_the_reset_pass,
    operate,
    redirect_register,
)

urlpatterns = [
    path("register", signup, name="register"),
    path('login', signin, name='login'),
    path('logout', logout_success, name='logout'),
    path('profile/<username>', profilePage, name='profile'),
    path('activate/<uidb64>/<token>', operate, name='activate'),
    path("password_change", change_the_pass, name="password_change"),
    path("password_reset", reset_the_pass, name="password_reset"),
    path('reset/<uidb64>/<token>', confirm_the_reset_pass, name='password_reset_confirm'),
    path('social/signup/', redirect_register, name='signup_redirect'),
]
