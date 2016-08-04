import logging

from django.contrib import auth
from django.views.decorators.csrf import csrf_exempt
from djangosaml2.conf import get_config
from djangosaml2.signals import post_authenticated
from djangosaml2.utils import get_custom_setting
from rest_framework import serializers, status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
from saml2 import BINDING_HTTP_POST
from saml2.client import Saml2Client

from nodeconductor.core.views import RefreshTokenMixin
from nodeconductor.core.serializers import Base64Field
from nodeconductor_saml2.log import event_logger


logger = logging.getLogger(__name__)


class Saml2ResponseSerializer(serializers.Serializer):
    saml2response = Base64Field(required=True)


class Saml2AuthView(RefreshTokenMixin, APIView):
    throttle_classes = ()
    permission_classes = ()
    serializer_class = Saml2ResponseSerializer

    @csrf_exempt
    def post(self, request):
        """SAML Authorization Response endpoint

        The IdP will send its response to this view, which
        will process it with pysaml2 help and log the user
        in using the custom Authorization backend
        djangosaml2.backends.Saml2Backend that should be
        enabled in the settings.py
        """
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            errors = dict(serializer.errors)

            try:
                non_field_errors = errors.pop('non_field_errors')
                errors['detail'] = non_field_errors[0]
            except (KeyError, IndexError):
                pass

            return Response(errors, status=status.HTTP_401_UNAUTHORIZED)

        attribute_mapping = get_custom_setting(
            'SAML_ATTRIBUTE_MAPPING', {'uid': ('username', )})
        create_unknown_user = get_custom_setting(
            'SAML_CREATE_UNKNOWN_USER', True)

        conf = get_config(request=request)
        client = Saml2Client(conf)

        xmlstr = serializer.validated_data['saml2response']

        # process the authentication response
        # noinspection PyBroadException
        try:
            response = client.parse_authn_request_response(xmlstr, BINDING_HTTP_POST)
        except Exception as e:
            logger.error('SAML response parsing failed %s' % e)
            response = None

        if response is None:
            return Response(
                {'saml2response': 'SAML2 response has errors.'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # authenticate the remote user
        session_info = response.session_info()

        user = auth.authenticate(
            session_info=session_info,
            attribute_mapping=attribute_mapping,
            create_unknown_user=create_unknown_user,
        )
        if user is None:
            logger.info('Authentication with SAML token has failed, user not found')
            return Response(
                {'detail': 'SAML2 authentication failed'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        post_authenticated.send_robust(sender=user, session_info=session_info)

        token = self.refresh_token(user)

        logger.info('Authenticated with SAML token. Returning token for successful login of user %s', user)
        event_logger.saml2_auth.info(
            'User {user_username} with full name {user_full_name} '
            'authenticated successfully with Omani PKI.',
            event_type='auth_logged_in_with_pki',
            event_context={'user': user})

        return Response({'token': token.key})

assertion_consumer_service = Saml2AuthView.as_view()
