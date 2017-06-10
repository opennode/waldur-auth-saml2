from celery import shared_task

from djangosaml2.conf import get_config
from djangosaml2.utils import available_idps

from . import models


@shared_task(name='nodeconductor_saml2.sync_providers')
def sync_providers():
    current_idps = list(models.IdentityProvider.objects.all().only('url', 'pk'))
    backend_idps = available_idps(get_config())

    backend_urls = set(backend_idps.keys())
    stale_idps = set(idp.pk for idp in current_idps if idp.url not in backend_urls)
    models.IdentityProvider.objects.filter(pk__in=stale_idps).delete()

    existing_urls = set(idp.url for idp in current_idps)
    missing_idps = [
        models.IdentityProvider(url=url, name=name)
        for (url, name) in backend_idps.items()
        if name and url not in existing_urls
    ]
    models.IdentityProvider.objects.bulk_create(missing_idps)
