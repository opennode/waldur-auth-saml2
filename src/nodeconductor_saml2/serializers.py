from djangosaml2.conf import get_config
from djangosaml2.utils import available_idps
from rest_framework import serializers

from nodeconductor.core.serializers import Base64Field


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


class Saml2ProviderSerializer(serializers.Serializer):

    def to_representation(self, instance):
        return instance

    def to_internal_value(self, data):
        return {
            'name': data[1],
            'url': data[0],
        }
