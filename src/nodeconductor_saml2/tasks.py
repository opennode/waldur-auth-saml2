from celery import shared_task
from django.conf import settings
from saml2.attribute_converter import ac_factory
from saml2.mdstore import MetaDataFile, name as get_idp_name

from . import models


def load_metadata():
    metadata = {}
    for filename in settings.NODECONDUCTOR_SAML2['idp_metadata_local']:
        mdf = MetaDataFile(ac_factory(), filename)
        mdf.load()
        metadata.update(mdf.items())
    return metadata


@shared_task(name='nodeconductor_saml2.sync_providers')
def sync_providers():
    mdf = load_metadata()

    current_idps = list(models.IdentityProvider.objects.all().only('url', 'pk'))
    backend_urls = set(mdf.keys())

    stale_idps = set(idp.pk for idp in current_idps if idp.url not in backend_urls)
    models.IdentityProvider.objects.filter(pk__in=stale_idps).delete()

    existing_urls = set(idp.url for idp in current_idps)
    missing_idps = []

    for url, metadata in mdf.items():
        name = get_idp_name(metadata)
        if not name:
            # It is expected that every provider has name.
            # Skip invalid identity provider
            continue
        if url in existing_urls:
            # Skip identity provider if its url is already in the database
            continue
        missing_idps.append(
            models.IdentityProvider(url=url, name=name, metadata=metadata)
        )
    models.IdentityProvider.objects.bulk_create(missing_idps)
