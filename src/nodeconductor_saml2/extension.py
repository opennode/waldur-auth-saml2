from nodeconductor.core import NodeConductorExtension


class SAML2Extension(NodeConductorExtension):

    @staticmethod
    def django_app():
        return 'nodeconductor_saml2'

    @staticmethod
    def django_urls():
        from .urls import urlpatterns
        return urlpatterns
