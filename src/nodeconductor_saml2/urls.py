from django.conf.urls import patterns, url

from .views import Saml2AuthView

urlpatterns = patterns('',
    url(r'^api-auth/saml2/', Saml2AuthView.as_view()),
)
