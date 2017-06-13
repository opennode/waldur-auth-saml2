from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from saml2.attribute_converter import ac_factory
from saml2.mdstore import InMemoryMetaData, MetaDataFile, name as get_idp_name

from . import models


def load_providers():
    metadata = {}
    for filename in settings.NODECONDUCTOR_SAML2['idp_metadata_local']:
        mdf = MetaDataFile(ac_factory(), filename)
        mdf.load()
        metadata.update(mdf.items())
    return metadata


def sync_providers():
    providers = load_providers()

    current_idps = list(models.IdentityProvider.objects.all().only('url', 'pk'))
    backend_urls = set(providers.keys())

    stale_idps = set(idp.pk for idp in current_idps if idp.url not in backend_urls)
    models.IdentityProvider.objects.filter(pk__in=stale_idps).delete()

    existing_urls = set(idp.url for idp in current_idps)

    for url, metadata in providers.items():
        name = get_idp_name(metadata)
        if not name:
            # It is expected that every provider has name.
            # Skip invalid identity provider
            continue
        if url in existing_urls:
            # Skip identity provider if its url is already in the database
            continue
        models.IdentityProvider.objects.create(url=url, name=name, metadata=metadata)

    for provider in models.IdentityProvider.objects.all().iterator():
        backend_metadata = providers.get(provider.url)
        if backend_metadata and provider.metadata != backend_metadata:
            provider.metadata = backend_metadata
            provider.save()


class DatabaseMetadataLoader(InMemoryMetaData):

    def load(self, *args, **kwargs):
        # Skip default parsing because data is not stored in file
        pass

    def __getitem__(self, item):
        try:
            return models.IdentityProvider.objects.get(url=item).metadata
        except ObjectDoesNotExist:
            raise KeyError
