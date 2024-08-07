import pytest
from mitmproxy.http import HTTPFlow, Response
from mitmproxy.test import taddons, tflow
from src.xepor import InterceptedAPI, HTTPVerb, RouteType

__author__ = "ttimasdf"
__copyright__ = "ttimasdf"
__license__ = "Apache-2.0"


@pytest.fixture
def api_simple():
    api = InterceptedAPI("example.com")

    @api.route("/test")
    def route1(flow: HTTPFlow):
        flow.response = Response.make(200, "TEST intercepted")

    @api.route(
        "/{}/{}/{vid}_1.m3u8",
        "hls.videocc.net",
    )
    def route2(flow: HTTPFlow, *args, vid):
        flow.response = Response.make(200, "TEST 2 INTERCEPTED")

    return api


@pytest.mark.parametrize(
    "req_url,resp_body",
    [
        ("http://example.com/test", "TEST intercepted"),
        (
                "http://hls.videocc.net/jkag324wd2/e/cwqzcxkvj0iukomqxu0l591u2dke4vkc_1.m3u8",
                "TEST 2 INTERCEPTED",
        ),
    ],
)
def test_intercepted_route(toptions, api_simple, req_url, resp_body):
    with taddons.context(api_simple, options=toptions) as tctx:
        flow = tflow.tflow()
        flow.request.url = req_url
        assert flow.response is None

        api_simple.request(flow)
        assert resp_body in flow.response.text


def test_non_intercepted_route(toptions, api_simple):
    with taddons.context(api_simple, options=toptions) as tctx:
        flow = tflow.tflow()
        flow.request.path = "/test2"
        assert flow.response is None

        api_simple.request(flow)
        assert flow.response is None


@pytest.fixture
def api_overwritten():
    api = InterceptedAPI("example.org")

    @api.route("/healthz", method=HTTPVerb.POST)
    def route1(flow: HTTPFlow):
        flow.response = Response.make(500, "Server Down")

    @api.route("/healthz", method=HTTPVerb.POST)
    def route1_alt(flow: HTTPFlow):
        flow.response = Response.make(200, "Server Up for requests")

    return api


@pytest.mark.parametrize(
    "req_url,resp_body",
    [
        ("http://example.org/healthz", "Server Up for requests"),
    ],
)
def test_route_replacement(toptions, api_overwritten, req_url, resp_body):
    with taddons.context(api_overwritten, options=toptions) as tctx:
        flow = tflow.tflow()
        flow.request.url = req_url
        flow.request.method = "POST"
        assert flow.response is None

        api_overwritten.request(flow)
        assert resp_body in flow.response.text


@pytest.fixture
def api_methods():
    api = InterceptedAPI("example.net")

    @api.route("/default", method=HTTPVerb.GET)
    def get(flow: HTTPFlow):
        flow.response = Response.make(200, "GET Successful")

    @api.route("/default", method="POST")
    def post(flow: HTTPFlow):
        flow.response = Response.make(200, "POST Successful")

    @api.route("/default", method=HTTPVerb.HEAD)
    def head(flow: HTTPFlow):
        flow.response = Response.make(200, "")

    @api.route("/default", method=HTTPVerb.OPTIONS)
    def options(flow: HTTPFlow):
        flow.response = Response.make(203, "OPTIONS")

    @api.route("/default", method=HTTPVerb.DELETE)
    def delete(flow: HTTPFlow):
        flow.response = Response.make(200, "deleted :(")

    @api.route("/posts", method=HTTPVerb.GET | HTTPVerb.POST)
    def get_post(flow: HTTPFlow):
        flow.response = Response.make(200, "All posts.")

    @api.route("/images", method="get|post")
    def get_image(flow: HTTPFlow):
        flow.response = Response.make(200, "All images.")

    @api.route("/statusz", method=["head", "OPTIONS", "trACE"])
    def get_status(flow: HTTPFlow):
        flow.response = Response.make(200, "ok")

    return api


@pytest.mark.parametrize(
    "req_url,method,resp_body",
    [
        ("http://example.net/default", "GET", "GET Successful"),
        ("http://example.net/default", "POST", "POST Successful"),
        ("http://example.net/default", "HEAD", ""),
        ("http://example.net/default", "OPTIONS", "OPTIONS"),
        ("http://example.net/default", "DELETE", "deleted :("),
    ],
)
def test_route_methods(toptions, api_methods, req_url, method, resp_body):
    with taddons.context(api_methods, options=toptions) as tctx:
        flow = tflow.tflow()
        flow.request.url = req_url
        flow.request.method = method
        assert flow.response is None

        api_methods.request(flow)
        assert resp_body in flow.response.text


def test_routes_methods_not_intercepted(toptions, api_methods):
    with taddons.context(api_methods, options=toptions) as tctx:
        expected_good = "All posts."

        for method in ["get", "post"]:
            flow = tflow.tflow()
            flow.request.url = "http://example.net/posts"

            flow.request.method = method.upper()
            assert flow.response is None

            api_methods.request(flow)
            assert expected_good in flow.response.text

        for method in ["put", "patch", "delete", "options", "head", "trace", "connect"]:
            flow = tflow.tflow()
            flow.request.url = "http://example.net/posts"

            flow.request.method = method.upper()
            assert flow.response is None

            api_methods.request(flow)
            assert flow.response is None


def test_routes_different_methods(toptions, api_methods):
    with taddons.context(api_methods, options=toptions) as tctx:
        expected_images, expected_status = "All images.", "ok"

        for method in ["get", "post"]:
            flow = tflow.tflow()
            flow.request.url = "http://example.net/images"

            flow.request.method = method.upper()
            assert flow.response is None

            api_methods.request(flow)
            assert expected_images in flow.response.text

        for method in ["options", "head", "trace"]:
            flow = tflow.tflow()
            flow.request.url = "http://example.net/statusz"

            flow.request.method = method.upper()
            assert flow.response is None

            api_methods.request(flow)
            assert expected_status in flow.response.text


@pytest.fixture
def api_overwritten_methods():
    api = InterceptedAPI("example.org")

    @api.route("/healthz", method=HTTPVerb.GET)
    def route1(flow: HTTPFlow):
        flow.response = Response.make(500, "healthy")

    @api.route("/healthz", method=HTTPVerb.ANY)
    def route2(flow: HTTPFlow):
        flow.response = Response.make(200, "healthy (default response)")

    @api.route("/healthz", method=HTTPVerb.POST)
    def route3(flow: HTTPFlow):
        flow.response = Response.make(
            500, f"hi {flow.request.multipart_form.get('name')}: healthy"
        )

    return api


def test_routes_methods_with_priority(toptions, api_overwritten_methods):
    with taddons.context(api_overwritten_methods, options=toptions) as tctx:
        num_routes = len(api_overwritten_methods.request_routes)
        assert num_routes == 3, f"Expected 3 routes, got {num_routes}"

        route_methods = [
            method for (_, _, method, _, _) in api_overwritten_methods.request_routes
        ]
        assert route_methods == [
            HTTPVerb.GET,
            HTTPVerb.ANY & ~HTTPVerb.GET & ~HTTPVerb.POST,
            HTTPVerb.POST,
        ]

        for method, expected_data in [
            ("get", "healthy"),
            ("post", "hi"),
            ("options", "healthy (default response)"),
        ]:
            flow = tflow.tflow()
            flow.request.url = "http://example.org/healthz"

            flow.request.method = method.upper()
            assert flow.response is None

            api_overwritten_methods.request(flow)
            # assert
            assert expected_data in flow.response.text


@pytest.fixture
def api_status_codes():
    api = InterceptedAPI("example.org")

    @api.route("/status")
    def req(flow: HTTPFlow):
        if flow.request.query.get("fail") is not None:
            flow.response = Response.make(400, "failed")
            return
        flow.response = Response.make(200, "ok")
        return

    @api.route("/status", rtype=RouteType.RESPONSE, allowed_statuses=[200])
    def resp(flow: HTTPFlow):
        if flow.response.status_code == 200:
            flow.response.content = b"intercepted"

    return api

def test_routes_methods_with_statuses(toptions, api_status_codes):
    with taddons.context(api_status_codes, options=toptions) as tctx:
        flow = tflow.tflow()
        flow.request.url = "http://example.org/status"

        api_status_codes.request(flow)
        assert flow.response.status_code == 200
        assert flow.response.text == "ok"
        api_status_codes.response(flow)
        assert flow.response.text == "intercepted"

        flow = tflow.tflow()
        flow.request.url = "http://example.org/status?fail=1"

        api_status_codes.request(flow)
        api_status_codes.response(flow)
        assert flow.response.status_code == 400
        assert flow.response.text == "failed"
