from django.db import models


class IdentityProvider(models.Model):
    name = models.TextField(db_index=True)
    url = models.URLField()

    class Meta(object):
        ordering = ('name',)
