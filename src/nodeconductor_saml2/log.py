from nodeconductor.core.models import User
from nodeconductor.logging.loggers import EventLogger, event_logger


class Saml2AuthEventLogger(EventLogger):
    user = User

    class Meta:
        event_types = ('auth_logged_in_with_saml2', 'auth_logged_out_with_saml2')


event_logger.register('saml2_auth', Saml2AuthEventLogger)
