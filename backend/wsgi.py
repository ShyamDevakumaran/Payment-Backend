"""
WSGI config for backend project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.0/howto/deployment/wsgi/
"""

from django.core.wsgi import get_wsgi_application
import os


import dotenv

dotenv.load_dotenv()


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings.development')

if os.getenv('DJANGO_SETTINGS_MODULE'):
    os.environ['DJANGO_SETTINGS_MODULE'] = os.getenv('DJANGO_SETTINGS_MODULE')


application = get_wsgi_application()
