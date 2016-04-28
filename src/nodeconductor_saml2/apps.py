from django.apps import AppConfig


class SAML2Config(AppConfig):
    name = 'nodeconductor_saml2'
    verbose_name = 'SAML2'

    def ready(self):
        pass
