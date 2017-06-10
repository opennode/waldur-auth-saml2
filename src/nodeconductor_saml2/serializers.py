from djangosaml2.conf import get_config
from djangosaml2.utils import available_idps
from rest_framework import serializers

from nodeconductor.core.serializers import Base64Field
from . import models


class Saml2LoginSerializer(serializers.Serializer):
    idp = serializers.ChoiceField(
        choices=available_idps(get_config()).items(),
    )


class Saml2LoginCompleteSerializer(serializers.Serializer):
    SAMLResponse = Base64Field()


class Saml2LogoutCompleteSerializer(serializers.Serializer):
    SAMLResponse = Base64Field(required=False)
    SAMLRequest = Base64Field(required=False)

    def validate(self, attrs):
        if not attrs.get('SAMLResponse') and not attrs.get('SAMLRequest'):
            raise serializers.ValidationError('Either SAMLResponse or SAMLRequest must be provided.')

        return attrs


class Saml2ProviderSerializer(serializers.ModelSerializer):
    class Meta(object):
        model = models.IdentityProvider
        fields = ('name', 'url')
