"""Settings for the standalone test project.

Deliberately minimal: sqlite in memory, the local-memory cache and no third
party apps, so ``pytest`` runs anywhere without a database or Redis server.
"""

SECRET_KEY = "django-bouncer-test-key-not-secret"
DEBUG = False
ALLOWED_HOSTS = ["*", "testserver"]

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.admin",
    "django_bouncer",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django_bouncer.middleware.ClientIPMiddleware",
    "django_bouncer.middleware.IPBanMiddleware",
    "django_bouncer.middleware.HoneypotMiddleware",
    "django_bouncer.middleware.JSONRequestValidationMiddleware",
    "django_bouncer.middleware.WAFMiddleware",
    "django_bouncer.middleware.BotDetectorMiddleware",
    "django_bouncer.middleware.RateLimitMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

ROOT_URLCONF = "tests.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "django-bouncer-tests",
    }
}

PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

LANGUAGE_CODE = "en"
LANGUAGES = [("en", "English"), ("tr", "Türkçe")]
USE_I18N = True
USE_TZ = True
TIME_ZONE = "UTC"

STATIC_URL = "/static/"
MEDIA_URL = "/media/"

LOGIN_URL = "/accounts/login/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
