import logging

import six
from django.conf import settings
from django.contrib import auth
from django.http import HttpResponseRedirect
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.csrf import csrf_exempt
from djangosaml2.cache import OutstandingQueriesCache, IdentityCache, StateCache
from djangosaml2.conf import get_config
from djangosaml2.signals import post_authenticated
from djangosaml2.utils import get_custom_setting, get_location, get_idp_sso_supported_bindings
from djangosaml2.views import _set_subject_id, _get_subject_id
from rest_framework.authtoken.models import Token
from rest_framework.generics import ListAPIView
from rest_framework.views import APIView
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.xmldsig import SIG_RSA_SHA1

from nodeconductor.core.views import RefreshTokenMixin

from . import filters, models, serializers
from .log import event_logger


logger = logging.getLogger(__name__)


def redirect_with(url_template, **kwargs):
    params = six.moves.urllib.parse.urlencode(kwargs)
    url = '%s?%s' % (url_template, params)
    return HttpResponseRedirect(url)


def login_completed(token):
    url_template = settings.NODECONDUCTOR_SAML2['LOGIN_COMPLETED_URL']
    url = url_template.format(token=token)
    return HttpResponseRedirect(url)


def login_failed(message):
    url_template = settings.NODECONDUCTOR_SAML2['LOGIN_FAILED_URL']
    return redirect_with(url_template, message=message)


def logout_completed():
    return HttpResponseRedirect(settings.NODECONDUCTOR_SAML2['LOGOUT_COMPLETED_URL'])


def logout_failed(message):
    url_template = settings.NODECONDUCTOR_SAML2['LOGOUT_FAILED_URL']
    return redirect_with(url_template, message=message)


class Saml2LoginView(APIView):
    """
    SAML Authorization endpoint
    
    This view receives authorization requests from users and 
    redirects them to corresponding IdP authorization page.
    The "metadata" has to be set in SAML_CONFIG in settings.py
    """
    throttle_classes = ()
    permission_classes = ()
    serializer_class = serializers.Saml2LoginSerializer

    @csrf_exempt
    def post(self, request):
        if not self.request.user.is_anonymous:
            return login_failed(_('This endpoint is for anonymous users only.'))

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        idp = serializer.validated_data.get('idp')

        conf = get_config(request=request)
        sign_requests = getattr(conf, '_sp_authn_requests_signed', False)

        # ensure our selected binding is supported by the IDP
        supported_bindings = get_idp_sso_supported_bindings(idp, config=conf)
        if BINDING_HTTP_REDIRECT in supported_bindings:
            binding = BINDING_HTTP_REDIRECT
        else:
            return login_failed(_('Identity provider does not support available bindings.'))

        client = Saml2Client(conf)
        sigalg = SIG_RSA_SHA1 if sign_requests else None
        session_id, result = client.prepare_for_authenticate(
            entityid=idp, binding=binding, sign=False, sigalg=sigalg)

        # save session_id
        oq_cache = OutstandingQueriesCache(request.session)
        oq_cache.set(session_id, '')

        return HttpResponseRedirect(get_location(result))


class Saml2LoginCompleteView(RefreshTokenMixin, APIView):
    """
    SAML Authorization Response endpoint

    The IdP will send its response to this view, which
    will process it with pysaml2 help and log the user
    in using the custom Authorization backend
    djangosaml2.backends.Saml2Backend that should be
    enabled in the settings.py
    """
    throttle_classes = ()
    permission_classes = ()
    serializer_class = serializers.Saml2LoginCompleteSerializer

    @csrf_exempt
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        attribute_mapping = get_custom_setting(
            'SAML_ATTRIBUTE_MAPPING', {'uid': ('username', )})
        create_unknown_user = get_custom_setting(
            'SAML_CREATE_UNKNOWN_USER', True)

        conf = get_config(request=request)
        client = Saml2Client(conf, identity_cache=IdentityCache(request.session))

        oq_cache = OutstandingQueriesCache(request.session)
        outstanding_queries = oq_cache.outstanding_queries()

        xmlstr = serializer.validated_data['SAMLResponse']

        # process the authentication response
        try:
            response = client.parse_authn_request_response(xmlstr, BINDING_HTTP_POST, outstanding_queries)
        except Exception as e:
            logger.error('SAML response parsing failed %s' % e)
            return login_failed(_('SAML2 response has errors.'))

        if response is None:
            logger.error('SAML response is None')
            return login_failed(_('SAML response has errors. Please check the logs'))

        if response.assertion is None:
            logger.error('SAML response assertion is None')
            return login_failed(_('SAML response has errors. Please check the logs'))

        session_id = response.session_id()
        oq_cache.delete(session_id)

        # authenticate the remote user
        session_info = response.session_info()

        if callable(attribute_mapping):
            attribute_mapping = attribute_mapping()
        if callable(create_unknown_user):
            create_unknown_user = create_unknown_user()

        user = auth.authenticate(
            session_info=session_info,
            attribute_mapping=attribute_mapping,
            create_unknown_user=create_unknown_user,
        )
        if user is None:
            return login_failed(_('SAML2 authentication failed.'))

        registration_method = settings.NODECONDUCTOR_SAML2.get('name', 'saml2')
        if user.registration_method != registration_method:
            user.registration_method = registration_method
            user.save(update_fields=['registration_method'])

        post_authenticated.send_robust(sender=user, session_info=session_info)
        token = self.refresh_token(user)
        # required for validating SAML2 logout requests
        _set_subject_id(request.session, session_info['name_id'])

        logger.info('Authenticated with SAML token. Returning token for successful login of user %s', user)
        event_logger.saml2_auth.info(
            'User {user_username} with full name {user_full_name} logged in successfully with SAML2.',
            event_type='auth_logged_in_with_saml2', event_context={'user': user}
        )
        return login_completed(token.key)


class Saml2LogoutView(APIView):
    """
    SAML Logout endpoint

    This view redirects users to corresponding IdP page for the logout.
    """
    throttle_classes = ()

    def get(self, request):
        state = StateCache(request.session)
        conf = get_config(request=request)

        client = Saml2Client(conf, state_cache=state, identity_cache=IdentityCache(request.session))
        subject_id = _get_subject_id(request.session)
        if subject_id is None:
            return logout_failed(_('You cannot be logged out.'))

        result = client.global_logout(subject_id)
        state.sync()
        if not result:
            return logout_failed(_('You are not logged in any IdP/AA.'))

        # Logout is supported only from 1 IdP
        binding, http_info = result.values()[0]
        return HttpResponseRedirect(get_location(http_info))


class Saml2LogoutCompleteView(APIView):
    """
    SAML Logout Response endpoint

    The IdP will send its response to this view, which
    will logout the user and remove authorization token.
    """

    throttle_classes = ()
    serializer_class = serializers.Saml2LogoutCompleteSerializer

    def get(self, request):
        """
        For IdPs which send GET requests
        """
        serializer = self.serializer_class(data=request.GET)
        serializer.is_valid(raise_exception=True)
        return self.logout(request, serializer.validated_data, BINDING_HTTP_REDIRECT)

    @csrf_exempt
    def post(self, request):
        """
        For IdPs which send POST requests
        """
        serializer = self.serializer_class(data=request.POST)
        serializer.is_valid(raise_exception=True)
        return self.logout(request, serializer.validated_data, BINDING_HTTP_POST)

    def logout(self, request, data, binding):
        conf = get_config(request=request)

        state = StateCache(request.session)
        client = Saml2Client(conf, state_cache=state,
                             identity_cache=IdentityCache(request.session))

        if 'SAMLResponse' in data:
            # Logout started by us
            response = client.parse_logout_request_response(data['SAMLResponse'], binding)
            http_response = logout_completed()
        else:
            # Logout started by IdP
            subject_id = _get_subject_id(request.session)
            if subject_id is None:
                http_response = logout_completed()
            else:
                http_info = client.handle_logout_request(data['SAMLRequest'], subject_id, binding,
                                                         relay_state=data.get('RelayState', ''))
                http_response = HttpResponseRedirect(get_location(http_info))

        state.sync()
        user = request.user
        Token.objects.get(user=user).delete()
        auth.logout(request)
        event_logger.saml2_auth.info(
            'User {user_username} with full name {user_full_name} logged out successfully with SAML2.',
            event_type='auth_logged_out_with_saml2', event_context={'user': user}
        )
        return http_response


class Saml2ProviderView(ListAPIView):
    throttle_classes = ()
    permission_classes = ()
    serializer_class = serializers.Saml2ProviderSerializer
    queryset = models.IdentityProvider.objects.all()
    filter_class = filters.IdentityProviderFilter
