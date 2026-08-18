from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class BouncerConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "django_bouncer"
    label = "django_bouncer"
    verbose_name = _("Bouncer (security & WAF)")

    def ready(self):
        # Importing for the side effect is the documented pattern for both
        # system checks and signal receivers.
        from . import checks, signals  # noqa: F401
