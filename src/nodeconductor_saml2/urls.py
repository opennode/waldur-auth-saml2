from django.conf.urls import patterns

urlpatterns += patterns(
    url(r'^api-auth/saml2/', 'nodeconductor_saml2.views.assertion_consumer_service'),
)
