"""django-bouncer — a second line of defence for Django applications.

The public surface lives in submodules; importing this package must stay free
of Django settings access so it can be imported before ``django.setup()``.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
