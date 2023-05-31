from .base import *
# don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = ['localhost']

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = os.environ.get('EMAIL_HOST')
EMAIL_PORT = os.environ.get('EMAIL_PORT')
EMAIL_USE_TLS = os.environ.get('EMAIL_USE_TLS')
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL')

DATABASES = {
    'default': {
        'ENGINE': os.environ.get('SQL_ENGINE'),
        'NAME': os.environ.get('SQL_DATABASE'),
        'USER': os.environ.get('SQL_USER',),
        'PASSWORD': os.environ.get('SQL_PASSWORD'),
        'HOST': os.environ.get('SQL_HOST',),
        'PORT': os.environ.get('SQL_PORT',),
    }
}


CORS_ORIGIN_WHITELIST = eval(os.environ.get('CORS_WHITELIST'))

SECURE_SSL_REDIRECT = eval(os.environ.get('SECURE_SSL_REDIRECT'))

SESSION_COOKIE_SECURE = eval(os.environ.get('SESSION_COOKIE_SECURE'))

CSRF_COOKIE_SECURE = eval(os.environ.get('CSRF_COOKIE_SECURE'))

SECURE_BROWSER_XSS_FILTER = eval(os.environ.get('SECURE_BROWSER_XSS_FILTER'))

SECURE_CONTENT_TYPE_NOSNIFF = eval(
    os.environ.get('SECURE_CONTENT_TYPE_NOSNIFF'))

SECURE_HSTS_SECONDS = os.environ.get('SECURE_HSTS_SECONDS')

SECURE_HSTS_PRELOAD = eval(os.environ.get('SECURE_HSTS_PRELOAD'))

SECURE_HSTS_INCLUDE_SUBDOMAINS = eval(
    os.environ.get('SECURE_HSTS_INCLUDE_SUBDOMAINS'))
