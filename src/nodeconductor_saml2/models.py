from django.db import models

from nodeconductor.core import fields as core_fields


class IdentityProvider(models.Model):
    name = models.TextField(db_index=True)
    url = models.URLField()
    metadata = core_fields.JSONField(default={})

    class Meta(object):
        ordering = ('name',)
