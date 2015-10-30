from django.conf.urls import url

from .views import Saml2AuthView

urlpatterns = (
    url(r'^api-auth/saml2/', Saml2AuthView.as_view()),
)
