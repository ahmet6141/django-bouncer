"""Template tags for django-bouncer."""
from django import template

from django_bouncer import policy

register = template.Library()


@register.inclusion_tag("django_bouncer/honeypot_field.html")
def bouncer_honeypot():
    """Render the hidden honeypot field.

    Usage::

        {% load bouncer %}
        <form method="post">{% csrf_token %}
          ...
          {% bouncer_honeypot %}
        </form>

    The field name comes from ``BOUNCER_HONEYPOT_FIELD_NAME``, so a project can
    pick something browser autofill will not recognise.
    """
    return {"field_name": policy.honeypot_field_name()}
