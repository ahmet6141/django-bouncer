"""URLconf for the test project."""
from django.contrib import admin
from django.http import HttpResponse
from django.urls import include, path


def ok(request):
    return HttpResponse("OK")


urlpatterns = [
    path("", ok, name="home"),
    path("accounts/login/", ok, name="login"),
    path("api/thing/", ok, name="api-thing"),
    path("admin/", admin.site.urls),
    path("bouncer/", include("django_bouncer.urls")),
]
