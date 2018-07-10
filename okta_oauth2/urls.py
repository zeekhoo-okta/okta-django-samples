from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.home_controller, name='home_controller'),
    url(r'^login', views.login_controller, name='login_controller'),
    url(r'^oauth2/callback', views.callback_controller, name='callback_controller'),
    url(r'^userinfo', views.userinfo_controller, name='userinfo_controller'),
    url(r'^introspect', views.introspect_controller, name='introspect_controller'),
    url(r'^revocation', views.revocation_controller, name='revocation_controller'),
    url(r'^logout/', views.logout_controller, name='logout_controller'),
]