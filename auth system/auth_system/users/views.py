from logging.config import valid_ident
from typing import Protocol
from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate, get_user_model
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import EmailMessage
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.db.models.query_utils import Q

from .forms import SignupForm, SignInForm, UserInfoUpdate, UpdatePass, PassResetForm
from .decorators import user_not_authenticated
from .tokens import account_activation_token



@user_not_authenticated
def signup(req):
    if req.method == "POST":
        form = SignupForm(req.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active=False
            user.save()
            operateEmail(req, user, form.cleaned_data.get('email'))
            return redirect('login')

        else:
            for error in list(form.errors.values()):
                messages.error(req, error)

    else:
        form = SignupForm()

    return render(
        request=req,
        template_name="register.html",
        context={"form": form}
        )


@login_required
def logout_success(request):
    logout(request)
    messages.info(request, "Logout!")
    return redirect("login")


@user_not_authenticated
def signin(req):
    if req.method == "POST":
        form = SignInForm(request=req, data=req.POST)
        if form.is_valid():
            user = authenticate(
                username=form.cleaned_data["username"],
                password=form.cleaned_data["password"],
            )
            if user is not None:
                login(req, user)
                messages.success(req, f"Merhaba <b>{user.username}</b>! Giriş yaptınız")
                return redirect("homepage")

        else:
            for key, error in list(form.errors.items()):
                if key == 'captcha' and error[0] == 'Bu alan gereklidir.':
                    messages.error(req, "reCAPTCHA testini geçmelisiniz")
                    continue
                
                messages.error(req, error) 

    form = SignInForm()

    return render(
        request=req,
        template_name="login.html",
        context={"form": form}
        )

def profilePage(req, username):
    if req.method == "POST":
        user = req.user
        form = UserInfoUpdate(req.POST, req.FILES, instance=user)
        if form.is_valid():
            user_form = form.save()
            messages.success(req, f'{user_form.username}, Profiliniz güncellendi!')
            return redirect("profile", user_form.username)

        for error in list(form.errors.values()):
            messages.error(req, error)

    user = get_user_model().objects.filter(username=username).first()
    if user:
        form = UserInfoUpdate(instance=user)
        form.fields['description'].widget.attrs = {'rows': 1}
        return render(
            request=req,
            template_name="profile.html",
            context={"form": form}
            )
    
    return redirect("profile")


@login_required
def logout_success(request):
    logout(request)
    messages.info(request, "Logout!")
    return redirect("login")
@login_required
def change_the_pass(req):
    user = req.user
    if req.method == 'POST':
        form = UpdatePass(user, req.POST)
        if form.is_valid():
            form.save()
            messages.success(req, "Şifreniz değiştirildi")
            return redirect('login')
        else:
            for error in list(form.errors.values()):
                messages.error(req, error)

    form = UpdatePass(user)
    return render(req, 'reset_the_pass_confirm.html', {'form': form})

@user_not_authenticated
def reset_the_pass(req):
    if req.method == 'POST':
        form = PassResetForm(req.POST)
        if form.is_valid():
            user_email = form.cleaned_data['email']
            associated_user = get_user_model().objects.filter(Q(email=user_email)).first()
            if associated_user:
                subject = "Password Reset request"
                message = render_to_string("reset_the_pass_temp.html", {
                    'user': associated_user,
                    'domain': "127.0.0.1:8000/",
                    'uid': urlsafe_base64_encode(force_bytes(associated_user.pk)),
                    'token': account_activation_token.make_token(associated_user),
                    "protocol": 'https' if req.is_secure() else 'http'
                })
                email = EmailMessage(subject, message, to=[associated_user.email])
                if email.send():
                    messages.success(req,
                        """
                        <h2>Şifre sıfırlama gönderildi</h2><hr>
                        <p>
                           Girdiğiniz e-posta adresiyle bir hesap mevcutsa, şifrenizi ayarlama talimatlarını size e-postayla gönderdik.
                             <br>E-posta almazsanız, lütfen adresi girdiğinizden emin olun.
                            spam klasörünüzü kontrol edin.
                        </p>
                        """
                    )
                else:
                    messages.error(req, "Şifre sıfırlama e-postası gönderilirken sorun oluştu, <b>SUNUCU SORUNU</b>")

            return redirect('homepage')

        for key, error in list(form.errors.items()):
            if key == 'captcha' and error[0] == 'Bu alan gereklidir.':
                messages.error(req, "reCAPTCHA testini geçmelisiniz")
                continue

    form = PassResetForm()
    return render(
        request=req, 
        template_name="reset_the_pass.html", 
        context={"form": form}
        )

def confirm_the_reset_pass(req, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except:
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        if req.method == 'POST':
            form = UpdatePass(user, req.POST)
            if form.is_valid():
                form.save()
                messages.success(req, "Şifreniz belirlendi. Şimdi devam edip <b>giriş yapabilirsiniz</b>.")
                return redirect('homepage')
            else:
                for error in list(form.errors.values()):
                    messages.error(req, error)

        form = UpdatePass(user)
        return render(req, 'reset_the_pass_confirm.html', {'form': form})
    else:
        messages.error(req, "Link is expired")

    messages.error(req, 'Bir şeyler ters gitti, Ana Sayfaya geri yönlendiriliyorsunuz')
    return redirect("homepage")


def operate(req, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except:
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()

        messages.success(req, "Giris Yapabilirsin.")
        return redirect('login')
    else:
        messages.error(req, "Link Gecersiz.")

    return redirect('login')

def operateEmail(req, user, to_email):
    mail_subject = "Hesabini Aktif Et."
    message = render_to_string("account_activat_temp.html", {
        'user': user.username,
        'domain': "127.0.0.1:8000/",
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': account_activation_token.make_token(user),
        "protocol": 'https' if req.is_secure() else 'http'
    })
    email = EmailMessage(mail_subject, message, to=[to_email])
    if email.send():
        messages.success(req, f'Sayin <b>{user}</b>, Email e git <b>{to_email}</b> inbox ini ac ve \
                link i onayla kayit islemini tamamla. <b>Not:</b> Spam dosyani kontrol et.')
    else:
        messages.error(req, f'Hata bu email e gonderilemedi {to_email}')



def redirect_register(req):
    messages.error(req, "zaten hesabınız var")
    return redirect("login")