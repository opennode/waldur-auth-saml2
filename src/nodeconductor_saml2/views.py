import logging

from django.contrib import auth
from django.http import HttpResponseRedirect
from django.views.decorators.csrf import csrf_exempt
from djangosaml2.cache import OutstandingQueriesCache, IdentityCache, StateCache
from djangosaml2.conf import get_config
from djangosaml2.signals import post_authenticated
from djangosaml2.utils import get_custom_setting, get_location
from djangosaml2.views import _set_subject_id, _get_subject_id
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client

from nodeconductor.core.views import RefreshTokenMixin

from . import serializers

logger = logging.getLogger(__name__)


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

    def post(self, request):
        if not self.request.user.is_anonymous():
            raise ValidationError('This endpoint is for anonymous users only.')

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        idp = serializer.validated_data.get('idp')

        conf = get_config(request=request)
        client = Saml2Client(conf)
        session_id, result = client.prepare_for_authenticate(entityid=idp)

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
            response = None

        if response is None:
            return Response(
                {'saml2response': 'SAML2 response has errors.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # authenticate the remote user
        session_info = response.session_info()

        user = auth.authenticate(
            session_info=session_info,
            attribute_mapping=attribute_mapping,
            create_unknown_user=create_unknown_user,
        )
        if user is None:
            return Response(
                {'detail': 'SAML2 authentication failed'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        post_authenticated.send_robust(sender=user, session_info=session_info)
        token = self.refresh_token(user)
        # required for validating SAML2 logout requests
        _set_subject_id(request.session, session_info['name_id'])

        logger.info('Authenticated with SAML token. Returning token for successful login of user %s', user)
        return Response({'token': token.key})


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
            return Response({'You cannot be logged out'}, status=status.HTTP_401_UNAUTHORIZED)

        result = client.global_logout(subject_id)
        state.sync()
        if not result:
            return Response({'You are not logged in any IdP/AA'}, status=status.HTTP_401_UNAUTHORIZED)

        # Logout is supported only from 1 IdP
        _, http_info = result.values()[0]
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

        # Logout started by us
        if 'SAMLResponse' in data:
            response = client.parse_logout_request_response(data['SAMLResponse'], binding)
            state.sync()
            Token.objects.get(user=request.user).delete()
            auth.logout(request)
            return Response({'detail': 'User has been logged out.'}, status=status.HTTP_200_OK)

        # Logout started by IdP
        if 'SAMLRequest' in data:
            subject_id = _get_subject_id(request.session)
            if subject_id is None:
                Token.objects.get(user=request.user).delete()
                auth.logout(request)
                return Response({'detail': 'User has been logged out.'}, status=status.HTTP_200_OK)

            http_info = client.handle_logout_request(data['SAMLRequest'], subject_id, binding,
                                                     relay_state=data.get('RelayState', ''))
            state.sync()
            Token.objects.get(user=request.user).delete()
            auth.logout(request)
            return HttpResponseRedirect(get_location(http_info))
