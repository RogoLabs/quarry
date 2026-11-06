"""IMPROVEMENT-PLAN items 12 and 20: routes from Django URLconf, Starlette Route/Mount and
NestJS controllers, and prefixes built from variables.

Each fixture is a small snippet in the shape real projects use: a Django project with
app URLconfs, a DRF router and a settings module; a Starlette app with nested Mounts; a
NestJS controller with guards and a global prefix. Ambiguous forms must add no prefix and
must be counted as unresolved, never guessed.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.dynamic.routes import StaticRouteSource, build_route_map   # noqa: E402
from quarry.dynamic.routes_py import (                                  # noqa: E402
    eval_prefix, regex_to_path, PyIndex)
from quarry.research import intent                                      # noqa: E402


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


def _discover(root: Path):
    src = StaticRouteSource()
    routes = src.discover(root)
    return src, routes


def _by(routes, method, path):
    hits = [r for r in routes if r.method == method and r.path == path]
    assert len(hits) == 1, (method, path, sorted((r.method, r.path) for r in routes))
    return hits[0]


def _line(text: str, needle: str) -> int:
    return text.splitlines().index(next(ln for ln in text.splitlines() if needle in ln)) + 1


# ------------------------------------------------------------------ Django

DJ_ROOT_URLS = '''\
from django.conf import settings
from django.contrib import admin
from django.contrib.auth.decorators import login_required
from django.urls import include, path, re_path
from django.views.generic import TemplateView

from blog import views as blog_views
from shop import urls as shop_urls

API_PREFIX = "api/"
API_V1 = f"{API_PREFIX}v1/"

urlpatterns = [
    path("admin/", admin.site.urls),
    path("blog/", include("blog.urls")),
    path("shop/", include(shop_urls)),
    path(API_V1, include("api.urls")),
    path("", blog_views.index, name="home"),
    path("profile/", login_required(blog_views.ProfileView.as_view())),
    path("about/", TemplateView.as_view(template_name="about.html")),
    path("old-home/", redirect_view("home")),
    re_path(r"^archive/(?P<year>[0-9]{4})/$", blog_views.archive),
    re_path(r"^(?!api|admin).*$", blog_views.spa),
]

if settings.DEBUG:
    urlpatterns += [path("debug/", blog_views.debug_view)]
'''

DJ_BLOG_URLS = '''\
from django.urls import include, path

from . import views

app_name = "blog"

drafts = [
    path("drafts/", views.drafts, name="drafts"),
]

urlpatterns = [
    path("<int:pk>/", views.PostDetail.as_view(), name="detail"),
    path("<int:pk>/edit/", views.PostEdit.as_view(), name="edit"),
    path("<int:pk>/delete/", views.PostDelete.as_view(), name="delete"),
    path("new/", views.create_post, name="create"),
    path("mine/", include(drafts)),
]
'''

DJ_BLOG_VIEWS = '''\
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import login_required, permission_required, user_passes_test
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.http import require_POST
from django.views.generic import DeleteView, DetailView, UpdateView

from .models import Post


def index(request):
    return render(request, "index.html")


def archive(request, year):
    return render(request, "archive.html", {"q": request.GET.get("q")})


def spa(request):
    return render(request, "spa.html")


def debug_view(request):
    return HttpResponse("debug")


@login_required
def drafts(request):
    return render(request, "drafts.html")


@require_POST
@permission_required("blog.add_post", raise_exception=True)
def create_post(request):
    post = Post.objects.create(title=request.POST["title"])
    return redirect(post)


class PostDetail(DetailView):
    model = Post


class OwnerMixin:
    def get_queryset(self):
        return super().get_queryset().filter(author=self.request.user)


class PostEdit(LoginRequiredMixin, OwnerMixin, UpdateView):
    model = Post
    fields = ["title", "body"]


@method_decorator(staff_member_required, name="dispatch")
class PostDelete(PermissionRequiredMixin, DeleteView):
    model = Post
    permission_required = "blog.delete_post"

    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


class ProfileView(View):
    def get(self, request):
        return render(request, "profile.html")

    @method_decorator(user_passes_test(lambda u: u.is_active))
    def post(self, request):
        request.user.save()
        return redirect("/")
'''

DJ_SHOP_URLS = '''\
from django.conf.urls import url

from shop import views

urlpatterns = [
    url(r'^items/(?P<item_id>\\d+)/$', views.item),
    url(r'^cart/?$', views.cart),
]
'''

DJ_SHOP_VIEWS = '''\
def item(request, item_id):
    if request.method == "POST":
        return add_to_cart(request, item_id)
    return render(request, "item.html")


def cart(request):
    return render(request, "cart.html")
'''

DJ_API_URLS = '''\
from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import ArticleViewSet, TagViewSet, ping, StatsView

router = DefaultRouter()
router.register(r"articles", ArticleViewSet, basename="article")
router.register("tags", TagViewSet)

urlpatterns = [
    path("", include(router.urls)),
    path("ping/", ping),
    path("stats/", StatsView.as_view()),
]
'''

DJ_API_VIEWS = '''\
from rest_framework import permissions, viewsets
from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.generics import ListAPIView


class ArticleViewSet(viewsets.ModelViewSet):
    authentication_classes = [TokenAuthentication]
    lookup_field = "slug"

    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)

    @action(detail=True, methods=["post"], permission_classes=[permissions.IsAdminUser])
    def publish(self, request, slug=None):
        return Response({"ok": True})


class TagViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [permissions.AllowAny]


@api_view(["GET"])
@permission_classes([permissions.AllowAny])
def ping(request):
    return Response({"pong": request.query_params.get("echo")})


class StatsView(ListAPIView):
    pass
'''

DJ_SETTINGS = '''\
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.auth.middleware.LoginRequiredMiddleware",
]

REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
}

ROOT_URLCONF = "mysite.urls"
'''


def _django(tmp_path: Path) -> Path:
    return _write(tmp_path, {
        "manage.py": "import os\n",
        "mysite/__init__.py": "",
        "mysite/settings.py": DJ_SETTINGS,
        "mysite/urls.py": DJ_ROOT_URLS,
        "blog/__init__.py": "",
        "blog/urls.py": DJ_BLOG_URLS,
        "blog/views.py": DJ_BLOG_VIEWS,
        "blog/models.py": "class Post: ...\n",
        "shop/__init__.py": "",
        "shop/urls.py": DJ_SHOP_URLS,
        "shop/views.py": DJ_SHOP_VIEWS,
        "api/__init__.py": "",
        "api/urls.py": DJ_API_URLS,
        "api/views.py": DJ_API_VIEWS,
    })


def test_django_urlconf_paths_with_include_prefixes(tmp_path):
    _, routes = _discover(_django(tmp_path))
    got = {(r.method, r.path) for r in routes}
    # include() with a module string, an imported module, and an inline named list
    assert ("GET", "/blog/<int:pk>/") in got
    assert ("GET", "/blog/mine/drafts/") in got
    assert ("GET", "/shop/items/<item_id>/") in got           # legacy url() regex
    assert ("GET", "/shop/cart") in got                        # optional slash left out
    assert ("POST", "/shop/items/<item_id>/") in got           # request.method == "POST"
    # module-level constants and an f-string of them as the include prefix
    assert ("GET", "/api/v1/articles/") in got
    # the root URLconf's own routes, and one added under `if settings.DEBUG:`
    assert {("GET", "/"), ("GET", "/archive/<year>/"), ("GET", "/debug/")} <= got
    # an installed app's URLconf (admin.site.urls) is not in the tree: no route
    assert not any(p.startswith("/admin") for _, p in got)
    # an included URLconf is reached only through its includer
    assert not any(p in ("/<int:pk>/", "/new/") for _, p in got)


def test_django_views_are_tied_to_their_handler_lines(tmp_path):
    root = _django(tmp_path)
    _, routes = _discover(root)
    create = _by(routes, "POST", "/blog/new/")
    assert create.handler_file == "blog/views.py" and create.handler == "create_post"
    assert create.line == _line(DJ_BLOG_VIEWS, "@require_POST")
    body = _line(DJ_BLOG_VIEWS, 'Post.objects.create(title=')
    assert create.encloses("blog/views.py", body)
    assert not any(r.encloses("blog/views.py", body) for r in routes if r is not create)
    assert [r.method for r in routes if r.path == "/blog/new/"] == ["POST"]   # require_POST
    # a class view gets one route per verb; its own method's lines when it defines one
    edit = {r.method: r for r in routes if r.path == "/blog/<int:pk>/edit/"}
    assert set(edit) == {"GET", "POST"}                      # UpdateView
    assert edit["GET"].handler == "PostEdit"                 # inherited: the class span
    delete = {r.method: r for r in routes if r.path == "/blog/<int:pk>/delete/"}
    assert set(delete) == {"GET", "POST", "DELETE"}          # DeleteView
    assert delete["POST"].handler == "PostDelete.post"
    assert delete["POST"].line == _line(DJ_BLOG_VIEWS, "    def post(self, request, *args")
    # a view this tree does not define stays, tied to the URLconf line that declares it
    about = _by(routes, "GET", "/about/")
    assert about.handler_file == "mysite/urls.py"
    assert about.line == _line(DJ_ROOT_URLS, 'path("about/"')
    # a view factory called with a URL name is the view, not a wrapper around "home"
    old = _by(routes, "GET", "/old-home/")
    assert old.handler == 'redirect_view("home")' and old.guards == ()
    # query names a Django handler reads
    assert _by(routes, "GET", "/archive/<year>/").query == ("q",)


def test_django_declared_access_from_wrappers_decorators_mixins_and_settings(tmp_path):
    _, routes = _discover(_django(tmp_path))
    mw = "django.contrib.auth.middleware.LoginRequiredMiddleware (settings MIDDLEWARE in " \
         "mysite/settings.py, project-wide)"
    assert _by(routes, "GET", "/blog/mine/drafts/").guards == ("login_required",)
    assert _by(routes, "POST", "/blog/new/").guards == (
        'permission_required("blog.add_post", raise_exception=True)',)
    # OwnerMixin filters the queryset to the caller's rows: object-level access, by name
    assert _by(routes, "GET", "/blog/<int:pk>/edit/").guards == (
        "LoginRequiredMixin (mixin)", "OwnerMixin (mixin)")
    assert _by(routes, "DELETE", "/blog/<int:pk>/delete/").guards == (
        'method_decorator(staff_member_required, name="dispatch")',
        "PermissionRequiredMixin (mixin)",
        'permission_required = "blog.delete_post"')
    prof = {r.method: r for r in routes if r.path == "/profile/"}
    assert prof["GET"].guards == ("login_required",)          # the URLconf wrapper
    assert prof["POST"].guards == (
        "login_required", "method_decorator(user_passes_test(lambda u: u.is_active))")
    assert all(mw in r.app_guards for r in routes if r.handler_file.startswith(("blog", "api")))
    # DRF: the settings default applies only to a view that sets no permission_classes
    default = "DEFAULT_PERMISSION_CLASSES [\"rest_framework.permissions.IsAuthenticated\"]"
    art = _by(routes, "GET", "/api/v1/articles/")
    assert art.guards == ("authentication_classes = [TokenAuthentication]",)
    assert any(g.startswith(default) for g in art.app_guards)
    tags = _by(routes, "GET", "/api/v1/tags/")
    assert tags.guards == ("permission_classes = [permissions.AllowAny]",)
    assert not any(g.startswith(default) for g in tags.app_guards)
    ping = _by(routes, "GET", "/api/v1/ping/")
    assert ping.guards == ("permission_classes([permissions.AllowAny])",)
    assert not any(g.startswith(default) for g in ping.app_guards)
    assert ping.query == ("echo",)


def test_drf_router_generates_list_detail_and_action_routes(tmp_path):
    _, routes = _discover(_django(tmp_path))
    art = {(r.method, r.path) for r in routes if "/articles/" in r.path}
    assert art == {("GET", "/api/v1/articles/"), ("POST", "/api/v1/articles/"),
                   ("GET", "/api/v1/articles/<slug>/"), ("PUT", "/api/v1/articles/<slug>/"),
                   ("PATCH", "/api/v1/articles/<slug>/"),
                   ("DELETE", "/api/v1/articles/<slug>/"),
                   ("POST", "/api/v1/articles/<slug>/publish/")}
    tags = {(r.method, r.path) for r in routes if "/tags/" in r.path}
    assert tags == {("GET", "/api/v1/tags/"), ("GET", "/api/v1/tags/<pk>/")}  # read-only
    destroy = _by(routes, "DELETE", "/api/v1/articles/<slug>/")
    assert destroy.handler == "ArticleViewSet.destroy"
    assert destroy.line == _line(DJ_API_VIEWS, "def destroy")
    publish = _by(routes, "POST", "/api/v1/articles/<slug>/publish/")
    assert publish.guards[-1] == "action(permission_classes=[permissions.IsAdminUser])"
    assert _by(routes, "GET", "/api/v1/stats/").handler == "StatsView"   # ListAPIView


def test_an_inherited_verb_spans_the_class_head_not_its_sibling_methods(tmp_path):
    # Item 3: a probe decides only on the route that encloses the finding. A whole-class
    # span for the inherited `list` would also enclose `destroy`'s body.
    _, routes = _discover(_django(tmp_path))
    f = "api/views.py"
    in_destroy = _line(DJ_API_VIEWS, "return super().destroy(")
    attr = _line(DJ_API_VIEWS, 'lookup_field = "slug"')
    article = [r for r in routes if r.handler_file == f and r.handler.startswith("ArticleViewSet")]
    assert [r.method for r in article if r.encloses(f, in_destroy)] == ["DELETE"]
    inherited = [r for r in article if r.handler == "ArticleViewSet"]
    assert inherited and all(r.encloses(f, attr) for r in inherited)
    assert all(r.end_line < _line(DJ_API_VIEWS, "def destroy") for r in inherited)
    # a helper method no route serves alone is enclosed by none: needs-review, not a guess
    views = DJ_BLOG_VIEWS
    helper = _line(views, "return super().get_queryset().filter(")
    assert not any(r.encloses("blog/views.py", helper) for r in routes)


def test_django_patterns_that_are_not_paths_are_counted_not_rendered(tmp_path):
    src, routes = _discover(_django(tmp_path))
    assert not any("(?!" in r.path or ".*" in r.path for r in routes)
    assert any("mysite/urls.py" in u and "(?!api|admin)" in u for u in src.unresolved)
    assert regex_to_path(r"^articles/(?P<year>[0-9]{4})/(?P<slug>[\w-]+)/$") == \
        "articles/<year>/<slug>/"
    assert regex_to_path(r"^files/(\d+)/raw\.txt$") == "files/<arg1>/raw.txt"
    assert regex_to_path(r"^page(?:/(?P<n>\d+))?/$") == "page/"
    assert regex_to_path(r"^static/(?P<path>.*)$") == "static/<path>"
    assert regex_to_path(r"^(en|fr)/$") == "<arg1>/"          # a capture group is a parameter
    for not_a_path in (r"^(?!api).*$", r"^(?:en|fr)/$", r"^\d+/$", r"^a|b$", r"^x+/$"):
        assert regex_to_path(not_a_path) is None, not_a_path


def test_an_ambiguous_django_include_adds_no_prefix_and_is_counted(tmp_path):
    _write(tmp_path, {
        "site/urls.py": 'from django.urls import include, path\n'
                        'urlpatterns = [path("blog/", include("blog.urls"))]\n',
        "one/blog/urls.py": 'from django.urls import path\nfrom . import views\n'
                            'urlpatterns = [path("x/", views.x)]\n',
        "one/blog/views.py": "def x(request): ...\n",
        "two/blog/urls.py": 'from django.urls import path\nfrom . import views\n'
                            'urlpatterns = [path("y/", views.y)]\n',
        "two/blog/views.py": "def y(request): ...\n",
    })
    src, routes = _discover(tmp_path)
    x, y = _by(routes, "GET", "/x/"), _by(routes, "GET", "/y/")
    assert not x.prefix_resolved and not y.prefix_resolved
    assert not any(r.path.startswith("/blog/") for r in routes)
    assert any("include('blog.urls') matches 2 files" in u for u in src.unresolved)


def test_django_variable_prefixes_resolve_or_stay_unprefixed(tmp_path):
    _write(tmp_path, {
        "proj/urls.py": '''\
from django.conf import settings
from django.urls import include, path, re_path

from . import views
from .paths import USERS

BASE = "svc/"
BASE = "other/"
V2 = "api/" + "v2/"

def get_system_setting(name):
    return ""

urlpatterns = [
    path(V2, include("proj.api_urls")),
    path(settings.API_PREFIX, include("proj.legacy_urls")),
    path(BASE, views.twice),
    path(USERS, views.users),
    re_path(r"^{}admin/".format(get_system_setting("url_prefix")), views.admin_home),
    path("api/" + get_system_setting("v") + "/x/", views.middle),
]
''',
        "proj/paths.py": 'USERS = "people/"\n',
        "proj/views.py": "".join(f"def {n}(request): ...\n" for n in
                                 ("twice", "users", "admin_home", "middle", "a", "b")),
        "proj/api_urls.py": 'from django.urls import path\nfrom . import views\n'
                            'urlpatterns = [path("a/", views.a)]\n',
        "proj/legacy_urls.py": 'from django.urls import path\nfrom . import views\n'
                               'urlpatterns = [path("b/", views.b)]\n',
    })
    src, routes = _discover(tmp_path)
    paths = {r.path: r for r in routes}
    assert paths["/api/v2/a/"].prefix_resolved                 # a + concatenation
    assert paths["/people/"].prefix_resolved                   # a constant imported from one file
    # settings.API_PREFIX is not a constant this tree defines: no prefix, flagged
    assert paths["/b/"].prefix_resolved is False
    # assigned twice at module level: not a constant, so that route is not rendered
    assert not any(r.handler == "twice" for r in routes)
    # a leading piece that cannot be computed is left out and the rest kept, flagged
    assert paths["/admin/"].prefix_resolved is False
    # an unknown piece in the middle is not a prefix: the route is not rendered
    assert not any(r.handler == "middle" for r in routes)
    joined = "\n".join(src.unresolved)
    for expected in ("settings.API_PREFIX", "BASE", "get_system_setting(\"url_prefix\")",
                     "get_system_setting(\"v\")"):
        assert expected in joined, expected


def test_drf_registrations_inside_a_helper_with_an_imported_prefix(tmp_path):
    # DefectDojo's shape: the router is passed to add_*_urls helpers in each app, and
    # the registered prefix is a constant imported from the app's package.
    _write(tmp_path, {
        "dojo/urls.py": '''\
from django.urls import include, re_path
from rest_framework.routers import DefaultRouter

from dojo.finding.api.urls import add_finding_urls

v2_api = DefaultRouter(trailing_slash=False)
v2_api = add_finding_urls(v2_api)

urlpatterns = [re_path(r"^api/v2/", include(v2_api.urls))]
''',
        "dojo/finding/__init__.py": "",
        "dojo/finding/api/__init__.py": 'path = "findings"\n',
        "dojo/finding/api/urls.py": '''\
from dojo.finding.api import path
from dojo.finding.api.views import FindingViewSet


def add_finding_urls(router):
    router.register(path, FindingViewSet, basename="finding")
    return router
''',
        "dojo/finding/api/views.py": '''\
from rest_framework import mixins, viewsets


class FindingViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin,
                     viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated, UserHasFindingPermission)
''',
    })
    _, routes = _discover(tmp_path)
    assert {(r.method, r.path) for r in routes} == {
        ("GET", "/api/v2/findings"), ("GET", "/api/v2/findings/<pk>")}
    assert all(r.handler_file == "dojo/finding/api/views.py" for r in routes)


def test_the_django_route_intent_block_is_no_longer_empty(tmp_path):
    m = intent.build(_django(tmp_path))
    assert not m.error and m.reader_errors == []
    block = m.for_file("blog/views.py")
    assert "DELETE /blog/<int:pk>/delete/" in block
    assert "PermissionRequiredMixin (mixin)" in block
    assert "app- or project-wide, before it: django.contrib.auth.middleware." \
           "LoginRequiredMiddleware" in block
    assert "handler: PostDelete.post" in block
    summary = m.summary()
    assert summary["with_guards"] == summary["routes"] > 0
    assert summary["unresolved_prefixes"] >= 1                  # the (?!api|admin) pattern


# ------------------------------------------------------------------ Starlette

ST_APP = '''\
from starlette.applications import Starlette
from starlette.authentication import requires
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from app import users
from app.endpoints import ItemEndpoint
from app.config import settings

API = "/api"


@requires("authenticated")
async def homepage(request):
    return PlainTextResponse("hi")


routes = [
    Route("/", homepage),
    Mount(API, routes=[
        Route("/items/{item_id:int}", ItemEndpoint),
        Mount("/users", routes=users.routes, middleware=[Middleware(AdminOnly)]),
    ]),
    Mount(settings.EXTRA_PREFIX, routes=[Route("/extra", homepage)]),
    Mount("/static", app=StaticFiles(directory="static"), name="static"),
]

app = Starlette(routes=routes, middleware=[
    Middleware(AuthenticationMiddleware, backend=TokenBackend()),
])
'''

ST_USERS = '''\
from starlette.routing import Route


async def list_users(request):
    return JSONResponse([])


async def user(request):
    if request.method == "DELETE":
        return Response(status_code=204)
    return JSONResponse({"id": request.path_params["uid"]})


routes = [
    Route("/", list_users),
    Route("/{uid}", user, methods=["GET", "DELETE"]),
]
'''

ST_ENDPOINTS = '''\
from starlette.endpoints import HTTPEndpoint


class ItemEndpoint(HTTPEndpoint):
    async def get(self, request):
        return JSONResponse({})

    async def put(self, request):
        return JSONResponse({})
'''


def test_starlette_mounts_routes_and_endpoints(tmp_path):
    _write(tmp_path, {"app/__init__.py": "", "app/main.py": ST_APP,
                      "app/users.py": ST_USERS, "app/endpoints.py": ST_ENDPOINTS,
                      "app/config.py": "settings = Settings()\n"})
    src, routes = _discover(tmp_path)
    got = {(r.method, r.path) for r in routes}
    assert {("GET", "/"), ("GET", "/api/items/{item_id:int}"),
            ("PUT", "/api/items/{item_id:int}"), ("GET", "/api/users/"),
            ("GET", "/api/users/{uid}"), ("DELETE", "/api/users/{uid}")} <= got
    home = _by(routes, "GET", "/")
    assert home.guards == ('requires("authenticated")',) and home.handler == "homepage"
    assert "AuthenticationMiddleware (middleware)" in home.app_guards
    put = _by(routes, "PUT", "/api/items/{item_id:int}")
    assert put.handler_file == "app/endpoints.py" and put.handler == "ItemEndpoint.put"
    assert put.line == _line(ST_ENDPOINTS, "async def put")
    deluser = _by(routes, "DELETE", "/api/users/{uid}")
    assert deluser.handler_file == "app/users.py"
    assert "AdminOnly (middleware)" in deluser.app_guards
    # a Mount path that is not a constant of this tree: no prefix, flagged, counted
    extra = _by(routes, "GET", "/extra")
    assert extra.prefix_resolved is False
    assert any("settings.EXTRA_PREFIX" in u for u in src.unresolved)
    assert all(r.prefix_resolved for r in routes if r.path != "/extra")


def test_a_fastapi_sub_application_mount_prefixes_its_routes(tmp_path):
    _write(tmp_path, {"main.py": '''\
from fastapi import FastAPI

app = FastAPI()
v1 = FastAPI()
V2_PATH = "/v2"
v2 = FastAPI()


@v1.get("/items/{item_id}")
def item(item_id: int):
    return {}


@v2.get("/items")
def items():
    return []


app.mount("/v1", v1)
app.mount(V2_PATH, v2)
app.mount("/static", StaticFiles(directory="static"), name="static")
'''})
    _, routes = _discover(tmp_path)
    assert {r.path for r in routes} == {"/v1/items/{item_id}", "/v2/items"}


# ------------------------------------------------------------------ NestJS

NEST_MAIN = '''\
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { JwtAuthGuard } from './auth/jwt.guard';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.setGlobalPrefix('api', { exclude: ['health'] });
  app.useGlobalGuards(new JwtAuthGuard(app.get(Reflector)));
  await app.listen(3000);
}
bootstrap();
'''

NEST_CATS = '''\
import { Body, Controller, Delete, Get, HttpCode, Param, Post, Query, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ApiTags } from '@nestjs/swagger';

const CATS = 'cats';

@ApiTags('cats')
@Controller(CATS)
@UseGuards(RolesGuard)
export class CatsController {
  private readonly logger = new Logger(CatsController.name);

  constructor(private readonly catsService: CatsService) {}

  @Get()
  findAll(@Query('limit') limit: number, @Query('offset') offset: number): Promise<Cat[]> {
    return this.catsService.findAll(limit, offset);
  }

  @Get(':id')
  @UseGuards(AuthGuard('jwt'))
  findOne(@Param('id') id: string) {
    return this.catsService.findOne(id);
  }

  @Post()
  @Roles('admin')
  @HttpCode(204)
  async create(@Body() dto: CreateCatDto) {
    // the owner's check is in the service (an apostrophe in a comment)
    await this.catsService.create(dto);
  }

  @Delete([':id', 'by-id/:id'])
  @Public()
  remove(@Param('id') id: string) {
    return this.catsService.remove(id);
  }
}
'''

NEST_HEALTH = '''\
import { Controller, Get } from '@nestjs/common';

@Controller({ path: 'health', version: '1' })
export class HealthController {
  @Get()
  check() {
    return { ok: true };
  }
}
'''

NEST_ADMIN = '''\
import { Controller, Get } from '@nestjs/common';
import { config } from '../config';

@Controller(config.adminPath)
export class AdminController {
  @Get('users')
  users() {
    return [];
  }
}
'''


def test_nestjs_controllers_methods_guards_and_global_prefix(tmp_path):
    _write(tmp_path, {"src/main.ts": NEST_MAIN, "src/cats/cats.controller.ts": NEST_CATS,
                      "src/health/health.controller.ts": NEST_HEALTH,
                      "src/admin/admin.controller.ts": NEST_ADMIN,
                      "src/app.module.ts": "import { Module } from '@nestjs/common';\n"
                                           "@Module({ providers: [{ provide: APP_GUARD, "
                                           "useClass: ThrottlerGuard }] })\n"
                                           "export class AppModule {}\n"})
    src, routes = _discover(tmp_path)
    got = {(r.method, r.path) for r in routes}
    assert {("GET", "/api/cats"), ("GET", "/api/cats/:id"), ("POST", "/api/cats"),
            ("DELETE", "/api/cats/:id"), ("DELETE", "/api/cats/by-id/:id"),
            ("GET", "/health")} <= got                       # health is excluded
    find_all = _by(routes, "GET", "/api/cats")
    assert find_all.query == ("limit", "offset")
    assert find_all.guards == ("UseGuards(RolesGuard)",)    # ApiTags is documentation
    assert find_all.app_guards == ("ThrottlerGuard (global guard, src/app.module.ts)",
                                   "JwtAuthGuard (global guard, src/main.ts)")
    one = _by(routes, "GET", "/api/cats/:id")
    assert one.guards == ("UseGuards(RolesGuard)", "UseGuards(AuthGuard('jwt'))")
    assert one.handler == "CatsController.findOne"
    assert (one.line, one.end_line) == (_line(NEST_CATS, "@Get(':id')"),
                                        _line(NEST_CATS, "return this.catsService.findOne") + 1)
    body = _line(NEST_CATS, "return this.catsService.findOne")
    assert one.encloses("src/cats/cats.controller.ts", body)
    assert not _by(routes, "GET", "/api/cats").encloses("src/cats/cats.controller.ts", body)
    assert _by(routes, "POST", "/api/cats").guards == ("UseGuards(RolesGuard)", "Roles('admin')")
    assert "Public()" in _by(routes, "DELETE", "/api/cats/by-id/:id").guards
    # a controller path that is not a constant: no controller prefix, flagged, counted
    adm = _by(routes, "GET", "/api/users")
    assert adm.prefix_resolved is False
    assert any("config.adminPath" in u for u in src.unresolved)
    assert all(r.prefix_resolved for r in routes if r.handler != "AdminController.users")


def test_nestjs_global_prefix_that_is_not_a_constant_is_not_guessed(tmp_path):
    _write(tmp_path, {
        "src/main.ts": "import { NestFactory } from '@nestjs/core';\n"
                       "const app = await NestFactory.create(AppModule);\n"
                       "app.setGlobalPrefix(process.env.PREFIX);\n",
        "src/cats.controller.ts": NEST_HEALTH.replace("health", "cats"),
    })
    src, routes = _discover(tmp_path)
    r = _by(routes, "GET", "/cats")
    assert r.prefix_resolved is False
    assert any("setGlobalPrefix(process.env.PREFIX)" in u for u in src.unresolved)


# ------------------------------------------------------------------ variable prefixes elsewhere

def test_fastapi_and_flask_prefixes_from_module_constants(tmp_path):
    _write(tmp_path, {
        "app/__init__.py": "",
        "app/main.py": '''\
from fastapi import FastAPI

from app.core.config import settings
from app.routers import users, items

API_V1 = "/api/v1"
INTERNAL = API_V1 + "/internal"

app = FastAPI()
app.include_router(users.router, prefix=API_V1)
app.include_router(items.router, prefix=f"{INTERNAL}/stock")
app.include_router(users.admin, prefix=settings.API_V1_STR)
''',
        "app/routers/__init__.py": "",
        "app/routers/users.py": '''\
from fastapi import APIRouter, Depends

USERS = "/users"
router = APIRouter(prefix=USERS, dependencies=[Depends(get_db)])
admin = APIRouter(prefix="/admin")


@router.get("/{user_id}")
def read_user(user_id: int): ...


@admin.delete("/{user_id}")
def delete_user(user_id: int): ...
''',
        "app/routers/items.py": '''\
from fastapi import APIRouter
router = APIRouter()


@router.get("/items")
def items(): ...
''',
        "web/views.py": '''\
from flask import Blueprint

PREFIX = "/notes"
bp = Blueprint("notes", __name__, url_prefix=PREFIX)
other = Blueprint("other", __name__, url_prefix="/other")


@bp.route("/<int:nid>")
def note(nid): ...


@other.route("/ping")
def ping(): ...
''',
        "web/app.py": '''\
from web.views import bp, other

app.register_blueprint(bp)
app.register_blueprint(other, url_prefix=current_prefix())
''',
    })
    src, routes = _discover(tmp_path)
    by_path = {r.path: r for r in routes}
    assert by_path["/api/v1/users/{user_id}"].prefix_resolved
    assert by_path["/api/v1/internal/stock/items"].prefix_resolved
    assert by_path["/notes/<int:nid>"].prefix_resolved
    # settings.API_V1_STR (the FastAPI template's shape) is an attribute of a settings
    # object, not a constant: the router keeps only its own prefix, flagged
    assert by_path["/admin/{user_id}"].prefix_resolved is False
    # register_blueprint(url_prefix=<call>) replaces the blueprint's own prefix with
    # something unknown: the route is left unprefixed, not given /other
    assert by_path["/ping"].prefix_resolved is False and "/other/ping" not in by_path
    joined = "\n".join(src.unresolved)
    assert "prefix=settings.API_V1_STR" in joined and "url_prefix=current_prefix()" in joined


def test_express_mount_prefixes_from_constants_and_templates(tmp_path):
    _write(tmp_path, {
        "routes/users.js": "const router = require('express').Router()\n"
                           "router.get('/:id', h)\nmodule.exports = router\n",
        "routes/admin.js": "const router = require('express').Router()\n"
                           "router.delete('/cache', h)\nmodule.exports = router\n",
        "routes/legacy.js": "const router = require('express').Router()\n"
                            "router.get('/old', h)\nmodule.exports = router\n",
        "routes/open.js": "const router = require('express').Router()\n"
                          "router.get('/status', h)\nmodule.exports = router\n",
        "server.js": '''\
const express = require('express')
const { BASE_PATH } = require('./config')
const users = require('./routes/users')
const admin = require('./routes/admin')
const legacy = require('./routes/legacy')
const open = require('./routes/open')
const API = '/api'
const V2 = `${API}/v2`
const app = express()

app.use(V2 + '/users', users)
app.use(`${API}/admin`, admin)
app.use(BASE_PATH, legacy)
app.use(requireLogin, open)
''',
    })
    src, routes = _discover(tmp_path)
    by_path = {r.path: r for r in routes}
    assert by_path["/api/v2/users/:id"].prefix_resolved
    assert by_path["/api/admin/cache"].prefix_resolved
    # an imported UPPER_CASE name is a path constant this file does not define
    assert by_path["/old"].prefix_resolved is False
    assert any("app.use(BASE_PATH)" in u for u in src.unresolved)
    # a camelCase first argument is middleware: mounted at "/", nothing unresolved
    assert by_path["/status"].prefix_resolved
    assert not any("requireLogin" in u for u in src.unresolved)


def test_an_ambiguous_python_mount_target_is_now_counted(tmp_path):
    for d in ("a", "b"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "users.py").write_text(
            "router = APIRouter()\n@router.get('/x')\ndef x(): ...\n")
    (tmp_path / "main.py").write_text("from users import router\n"
                                      "app.include_router(router, prefix='/api')\n")
    src, routes = _discover(tmp_path)
    assert {(r.handler_file, r.path, r.prefix_resolved) for r in routes} == {
        ("a/users.py", "/x", False), ("b/users.py", "/x", False)}
    assert any("matches 2 files" in u for u in src.unresolved)


def test_eval_prefix_keeps_only_a_known_tail_behind_a_leading_unknown():
    import ast

    def ev(src, consts=None):
        return eval_prefix(ast.parse(src, mode="eval").body, consts or {})
    assert ev('"api/"') == ("api/", True)
    assert ev('A + "x/"', {"A": "api/"}) == ("api/x/", True)
    assert ev('f"{A}v1/"', {"A": "api/"}) == ("api/v1/", True)
    assert ev('"^{}api/v2/".format(get("p"))') == ("^api/v2/", False)
    assert ev('f"^{get()}api/"') == ("^api/", False)
    assert ev('settings.PREFIX') == (None, False)              # nothing known after it
    assert ev('"api/" + get() + "/x/"') == (None, False)       # unknown in the middle
    assert ev('"^{}".format(get())') == (None, False)
    assert ev('"{a}/x/".format(a=A)', {"A": "v"}) == ("v/x/", True)


def test_route_discovery_survives_a_reader_that_fails(tmp_path, monkeypatch):
    from quarry.dynamic import routes as R

    def boom(self):
        raise RuntimeError("django reader fell over")
    monkeypatch.setattr(R.Django, "run", boom)
    _write(tmp_path, {"api.py": "@app.get('/x')\ndef x(): ...\n",
                      "urls.py": "urlpatterns = []\n"})
    src, routes = _discover(tmp_path)
    assert [r.path for r in routes] == ["/x"]
    assert src.errors == ["django: RuntimeError: django reader fell over"]


def test_django_routes_merge_with_a_committed_spec(tmp_path):
    import json
    root = _django(tmp_path)
    (root / "openapi.json").write_text(json.dumps({
        "openapi": "3.0.0",
        "paths": {"/api/v1/articles/{slug}/": {"delete": {"security": [{"t": []}]}}}}))
    rmap = build_route_map(root)
    r = next(x for x in rmap.for_finding("api/views.py")
             if x.method == "DELETE" and x.path == "/api/v1/articles/<slug>/")
    assert r.source == "static+openapi" and r.auth_required is True
    assert r.handler == "ArticleViewSet.destroy"           # the merge keeps the handler
    assert PyIndex({"a.py": "X = 'y'\n"}).consts("a.py") == {"X": "y"}
