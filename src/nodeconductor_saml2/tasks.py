from celery import shared_task
import subprocess  # nosec


@shared_task(name='nodeconductor_saml2.sync_providers')
def sync_providers():
    # It is assumed that nodeconductor console script is installed
    command = ['nodeconductor', 'sync_saml2_providers']
    subprocess.check_output(command, stderr=subprocess.STDOUT)  # nosec
