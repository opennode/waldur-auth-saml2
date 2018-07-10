import saml2

WALDUR_AUTH_SAML2['IDENTITY_PROVIDER_URL'] = 'http://localhost:9080/simplesaml/saml2/idp/metadata.php'
WALDUR_AUTH_SAML2['IDENTITY_PROVIDER_LABEL'] = 'Test SAML2 IdP'

SAML_CONFIG['metadata'].append({
    'class': 'saml2.mdstore.MetaDataExtern',
    'metadata': [(
        'http://localhost:9080/simplesaml/saml2/idp/metadata.php',
        '/waldur-auth-saml2/docker_test/config/server.crt',
    )]
})

SAML_CONFIG['key_file'] = '/waldur-auth-saml2/docker_test/config/sp.pem'
SAML_CONFIG['cert_file'] = '/waldur-auth-saml2/docker_test/config/sp.crt'
SAML_CONFIG['encryption_keypairs'] = [{
    "key_file": '/waldur-auth-saml2/docker_test/config/sp.pem',
    "cert_file": '/waldur-auth-saml2/docker_test/config/sp.crt',
}]

SAML_CONFIG['entityid'] = 'http://127.0.0.1:8080/api-auth/saml2/metadata/'
SAML_CONFIG['debug'] = 1
SAML_CONFIG['service']['sp']['logout_requests_signed'] = True
SAML_CONFIG['service']['sp']['authn_requests_signed'] = True
SAML_CONFIG['service']['sp']['allow_unsolicited'] = True
SAML_CONFIG['service']['sp']['endpoints'] = {
    'assertion_consumer_service': [
        ('http://127.0.0.1:8080/api-auth/saml2/login/complete/', saml2.BINDING_HTTP_POST)
    ],
    'single_logout_service': [
        ('http://127.0.0.1:8080/api-auth/saml2/logout/complete/', saml2.BINDING_HTTP_REDIRECT),
        ('http://127.0.0.1:8080/api-auth/saml2/logout/complete/', saml2.BINDING_HTTP_POST),
    ],
}

SAML_ATTRIBUTE_MAPPING = {
    'uid': ('username',),
    'email': ('email',),
}

WALDUR_CORE['LOGIN_COMPLETED_URL'] = 'http://127.0.0.1:8001/#/login_completed/{token}/{method}/'
WALDUR_CORE['LOGIN_FAILED_URL'] = 'http://127.0.0.1:8001/#/login_failed/'
WALDUR_CORE['AUTHENTICATION_METHODS'] = ['LOCAL_SIGNIN', 'SAML2']
