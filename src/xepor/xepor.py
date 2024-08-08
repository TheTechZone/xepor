import functools
import logging
import os
import re
import sys
import traceback
import urllib.parse
from enum import StrEnum, Enum, IntFlag, auto
from typing import List, Optional, Tuple, Union, Callable

from mitmproxy import ctx
from mitmproxy.addonmanager import Loader
from mitmproxy.connection import Server
from mitmproxy.http import HTTPFlow, Response
from mitmproxy.net.http import url
from parse import Parser

__author__ = "ttimasdf"
__copyright__ = "ttimasdf"
__license__ = "Apache-2.0"


class RouteType(Enum):
    """
    This enum is an option set in route definition, specify it to be matched
    on either incoming request or response.
    """

    REQUEST = 1
    """The route will be matched on mitmproxy ``request`` event"""
    RESPONSE = 2
    """The route will be matched on mitmproxy ``response`` event"""


class HTTPVerb(IntFlag):
    GET = auto()
    HEAD = auto()
    POST = auto()
    PUT = auto()
    DELETE = auto()
    CONNECT = auto()
    OPTIONS = auto()
    TRACE = auto()
    PATCH = auto()

    ANY = GET | HEAD | POST | PUT | DELETE | CONNECT | OPTIONS | TRACE | PATCH

    # Class method to parse a string representation of flags
    @classmethod
    def parse_flags(cls, flags_str: str):
        # Split the input string by '|' to get individual flag names
        flags = flags_str.split("|")
        # Initialize an IntFlag instance with value 0
        parsed_flags = cls(0)
        # Iterate over the split flags and set the corresponding bits
        for flag_name in flags:
            # Remove leading/trailing whitespace and strip quotes if present
            flag_name = flag_name.strip().strip("'\"").upper()
            # Set the bit corresponding to the flag name
            parsed_flags |= getattr(cls, flag_name)
        return parsed_flags

    @classmethod
    def parse_list(cls, flags: list[str]):
        # Initialize an IntFlag instance with value 0
        parsed_flags = cls(0)
        # Iterate over the split flags and set the corresponding bits
        for flag_name in flags:
            # Remove leading/trailing whitespace and strip quotes if present
            flag_name = flag_name.strip().strip("'\"").upper()
            # Set the bit corresponding to the flag name
            parsed_flags |= getattr(cls, flag_name)
        return parsed_flags


class WSMsgType(IntFlag):
    TEXT = auto()
    BINARY = auto()
    ANY = TEXT | BINARY


class FlowMeta(StrEnum):
    """
    This class is used internally by Xepor to mark ``flow`` object by certain metadata.
    Refer to the source code for detailed usage.
    """

    REQ_PASSTHROUGH: str = "xepor-request-passthrough"
    RESP_PASSTHROUGH: str = "xepor-response-passthrough"
    REQ_URLPARSE: str = "xepor-request-urlparse"
    REQ_HOST: str = "xepor-request-host"


class Router:
    """
    Currently the routes makes abstraction of the direction of flow.
    """
    def __init__(self):
        self.routes: List[
            Tuple[Optional[str], Parser, HTTPVerb, callable, Optional[List[int]]]
        ] = []

    def add_route(self, host: str, path: Parser, method: HTTPVerb, handler: Callable,
                  allowed_statuses: Optional[List[int]]):
        self.routes.append(
            (host, path, method, handler, allowed_statuses)
        )

    def replace_route(self, host: str, path: Parser, new_handler: Callable, method: HTTPVerb,
                      allowed_statuses: List[int]) -> bool:
        partial_matches = []
        for i, (h, parser, m, handler, status_codes) in enumerate(self.routes):
            if (
                    h == host
                    and (method in m or m in method) #  handle both the case when the new route has higher or lower specificity
                    and parser.parse(path) is not None
            ):
                partial_matches.append([i, (h, parser, m, handler, status_codes)])

        if len(partial_matches) > 0:
            for i, (h, parser, m, handler, status_codes) in partial_matches:
                if method == m:
                    self.routes[i] = (h, parser, m, new_handler, allowed_statuses)
                    return True
                if method in m:
                    m = m & ~method
                    self.routes[i] = (h, parser, m, handler, status_codes)
                elif m in method:
                    method = method & ~m
            self.routes.append((host, Parser(path), method, new_handler, allowed_statuses))
            return True

        return False

    def find_handler(self, host: str, path: str, method=HTTPVerb.ANY) -> Tuple:
        for h, parser, m, handler, status_codes in self.routes:
            if h != host or method not in m:
                continue
            parse_result = parser.parse(path)
            if parse_result is not None:
                return handler, parse_result, status_codes

        return None, None, None

class WSRouter(Router):
    def __init__(self):
        super().__init__()
        self.routes: List[Tuple[Optional[str], Parser, WSMsgType, callable]] = []

    def add_route(self, host: str, path: Parser, mtype: WSMsgType, handler: Callable):
        self.routes.append((host, path, mtype, handler))

    def replace_route(self, host: str, path: Parser, new_handler: Callable, mtype: WSMsgType) -> bool:
        partial_matches = []

        for i, (h, parser, m, handler) in enumerate(self.routes):
            if (
                    h == host
                    and (mtype in m or m in mtype)
                    and parser.parse(path) is not None
            ):
                partial_matches.append([i, (h, parser, m, handler)])

        if len(partial_matches) > 0:
            for i, (h, parser, m, handler) in partial_matches:
                if mtype == m:
                    self.routes[i] = (
                        h,
                        parser,
                        m,
                        new_handler,
                    )
                    return True
                if mtype in m:
                    m = m & ~mtype
                    self.routes[i] = (h, parser, m, handler)
                elif m in mtype:
                    mtype = mtype & ~m
            self.routes.append(
                (
                    host,
                    Parser(path),
                    mtype,
                    new_handler,
                )
            )
            return True

        return False


    def find_handler(self, host: str, path: str, mtype: WSMsgType) -> Tuple:
        for h, parser, m, handler in self.routes:
            if h != host or mtype not in m:
                continue
            parse_result = parser.parse(path)
            if parse_result is not None:
                return handler, parse_result

        return None, None

class InterceptedAPI:
    """
    the InterceptedAPI object is the central registry of your view functions.
    Users should use a function decorator :func:`route` to define and register
    URL and host mapping to the view functions. Just like flask's :external:py:meth:`flask.Flask.route`.

    .. code-block:: python

        from xepor import InterceptedAPI, RouteType

        HOST_HTTPBIN = "httpbin.org"
        api = InterceptedAPI(HOST_HTTPBIN)

    Defining a constant for your target (victim) domain name is not mandatory
    (even the `default_host` parameter itself is optional) but
    recommended as best practise. If you have multiple hosts to inject
    (see an example at `xepor/xepor-examples/polyv_scrapper/polyv.py <https://github.com/xepor/xepor-examples/blob/306ffad36a9ff3db00eb44b67b8b83a85e234d6e/polyv_scrapper/polyv.py#L27-L29>`_), you would have to specify the domain name
    multiple times in each :func:`route` in `host` parameter,
    (especially for domains other than `default_host`).
    So it's better to have a variable for that.

    Add route via function call similar to Flask :external:py:meth:`flask.Flask.add_url_rule`
    is not yet implemented.

    :param default_host: The default host to forward requests to.
    :param host_mapping: A list of tuples of the form (regex, host) where regex
        is a regular expression to match against the request host and host is the
        host to redirect the request to.
    :param blacklist_domain: A list of domains to not forward requests to.
        The requests and response from hosts in this list will not respect
        :py:obj:`request_passthrough` and :py:obj:`response_passthrough` setting.
    :param request_passthrough: Whether to forward the request to upstream server
        if no route is found. If ``request_passthrough = False``, all requests not
        matching any route will be responded with :func:`default_response` without
        connecting to upstream.
    :param response_passthrough: Whether to forward the response to the user
        if no route is found. If ``response_passthrough = False``, all responses not
        matching any route will be replaced with the Response object
        generated by :func:`default_response`.
    :param respect_proxy_headers: Set to `True` only when you use Xepor as
        a web server behind a reverse proxy. Typical use case is to set up an
        mitmproxy in ``reverse`` mode to bypass some online license checks.
        Xepor will respect the following headers and strip them from requests to upstream.

        - `X-Forwarded-For`
        - `X-Forwarded-Host`
        - `X-Forwarded-Port`
        - `X-Forwarded-Proto`
        - `X-Forwarded-Server`
        - `X-Real-Ip`
    """

    _REGEX_HOST_HEADER = re.compile(r"^(?P<host>[^:]+|\[.+\])(?::(?P<port>\d+))?$")

    _PROXY_FORWARDED_HEADERS = [
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Forwarded-Port",
        "X-Forwarded-Proto",
        "X-Forwarded-Server",
        "X-Real-Ip",
    ]

    def __init__(
            self,
            default_host: Optional[str] = None,
            host_mapping: List[Tuple[Union[str, re.Pattern], str]] = {},
            blacklist_domain: List[str] = [],
            request_passthrough: bool = True,
            response_passthrough: bool = True,
            respect_proxy_headers: bool = False,
    ):

        self.default_host = default_host
        self.host_mapping = host_mapping
        # self.request_routes: List[
        #     Tuple[Optional[str], Parser, HTTPVerb, callable, Optional[List[int]]]
        # ] = []
        # self.response_routes: List[
        #     Tuple[Optional[str], Parser, HTTPVerb, callable, Optional[List[int]]]
        # ] = []
        self.request_routes = Router()
        self.response_routes = Router()

        # self.ws_request_routes: List[
        #     Tuple[Optional[str], Parser, WSMsgType, callable]
        # ] = []
        # self.ws_response_routes: List[
        #     Tuple[Optional[str], Parser, WSMsgType, callable]
        # ] = []
        self.ws_request_routes = WSRouter()
        self.ws_response_routes = WSRouter()

        self.blacklist_domain = blacklist_domain
        self.request_passthrough = request_passthrough
        self.response_passthrough = response_passthrough
        self.respect_proxy_headers = respect_proxy_headers

        self._log = logging.getLogger(__name__)
        if os.getenv("XEPOR_LOG_DEBUG"):
            self._log.setLevel(logging.DEBUG)
        self._log.info("%s started", self.__class__.__name__)

    def load(self, loader: Loader):
        """
        This function is called by the mitmproxy framework *before* proxy server started.
        Currently, it's used to set a must-have mitmproxy option for Xepor
        to work: ``connection_strategy=lazy``. If you want to override this method,
        remember to call ``super().load(loader)`` in your code.

        User can also import and use :py:data:`mitmproxy.ctx` object to configure
        other options for mitmproxy when overriding this function.

        .. code-block:: python

            from mitmproxy import ctx

            ctx.options.connection_strategy = "lazy"

        :param loader: a :py:class:`mitmproxy.addonmanager.Loader` which can be used to add custom options.
        :return: None
        """
        self._log.info("Setting option connection_strategy=lazy")
        ctx.options.connection_strategy = "lazy"

    # def server_connect(self, data: ServerConnectionHookData):
    #     self._log.debug("Getting connection: peer=%s sock=%s addr=%s . state=%s",
    #         data.server.peername, data.server.sockname, data.server.address, data.server)

    def request(self, flow: HTTPFlow):
        """
        This function is called by the mitmproxy framework whenever a request is made.

        :param flow: The :py:class:`mitmproxy.http.HTTPFlow` object from client request.
        :return: None
        """
        if FlowMeta.REQ_URLPARSE in flow.metadata:
            url = flow.metadata[FlowMeta.REQ_URLPARSE]
        else:
            url = urllib.parse.urlparse(flow.request.path)
            flow.metadata[FlowMeta.REQ_URLPARSE] = url
        path = url.path
        if flow.metadata.get(FlowMeta.REQ_PASSTHROUGH) is True:
            self._log.warning(
                "<= [%s] %s skipped because of previous passthrough",
                flow.request.method,
                path,
            )
            return
        host = self.remap_host(flow)
        handler, params, _ = self.find_handler(
            host, path, RouteType.REQUEST, HTTPVerb.parse_flags(flow.request.method)
        )
        if handler is not None:
            self._log.info("<= [%s] %s", flow.request.method, path)
            handler(flow, *params.fixed, **params.named)
        elif (
                not self.request_passthrough
                or self.get_host(flow)[0] in self.blacklist_domain
        ):
            self._log.warning("<= [%s] %s default response", flow.request.method, path)
            flow.response = self.default_response()
        else:
            flow.metadata[FlowMeta.REQ_PASSTHROUGH] = True
            self._log.debug("<= [%s] %s passthrough", flow.request.method, path)

    def response(self, flow: HTTPFlow):
        """
        This function is called by the mitmproxy when a response is returned the server.

        :param flow: The :py:class:`mitmproxy.http.HTTPFlow` object from server response.
        :return: None
        """
        if FlowMeta.REQ_URLPARSE in flow.metadata:
            url = flow.metadata[FlowMeta.REQ_URLPARSE]
        else:
            url = urllib.parse.urlparse(flow.request.path)
            flow.metadata[FlowMeta.REQ_URLPARSE] = url
        path = url.path
        if flow.metadata.get(FlowMeta.RESP_PASSTHROUGH) is True:
            self._log.warning(
                "=> [%s] %s skipped because of previous passthrough",
                flow.response.status_code,
                path,
            )
            return
        handler, params, allowed_codes = self.find_handler(
            self.get_host(flow)[0],
            path,
            RouteType.RESPONSE,
            HTTPVerb.parse_flags(flow.request.method),
        )
        if handler is not None:
            self._log.info("=> [%s] %s", flow.response.status_code, path)
            if allowed_codes and flow.response.status_code not in allowed_codes:
                self._log.warning(
                    "=> [%s] %s not in allowed status codes",
                    flow.response.status_code,
                    path,
                )
                return
            handler(flow, *params.fixed, **params.named)
        elif (
                not self.response_passthrough
                or self.get_host(flow)[0] in self.blacklist_domain
        ):
            self._log.warning(
                "=> [%s] %s default response", flow.response.status_code, path
            )
            flow.response = self.default_response()
        else:
            flow.metadata[FlowMeta.RESP_PASSTHROUGH] = True
            self._log.debug("=> [%s] %s passthrough", flow.response.status_code, path)


    def websocket_message(self, flow: HTTPFlow):
        ws = flow.websocket
        if not ws:
            self._log.warning(f"websocket flow is empty: {flow}")
            return
        msg = ws.messages[-1]
        is_request = msg.from_client
        direction = "<=" if is_request else "=>"

        if FlowMeta.REQ_URLPARSE in flow.metadata:
            url = flow.metadata[FlowMeta.REQ_URLPARSE]
        else:
            url = urllib.parse.urlparse(flow.request.path)
            flow.metadata[FlowMeta.REQ_URLPARSE] = url

        path = url.path
        # todo: check this later
        # if (is_request and flow.metadata.get(FlowMeta.REQ_PASSTHROUGH) is True) or (
        #         not is_request and flow.metadata.get(FlowMeta.RESP_PASSTHROUGH) is True):
        #     self._log.warning(
        #         "%s [%s] %s skipped because of previous passthrough",
        #         direction,
        #         flow.response.status_code,
        #         path,
        #     )
        #     return

        rtype = RouteType.REQUEST if is_request else RouteType.RESPONSE
        mtype = WSMsgType(int(msg.type))
        ws_handler, params = self.find_ws_handler(
            self.get_host(flow)[0], path, rtype, mtype
        )
        if ws_handler is not None:
            self._log.info("%s %s", direction, path)
            ws_handler(flow, *params.fixed, **params.named)
        elif (
                not self.request_passthrough or not self.response_passthrough
        ) or self.get_host(flow)[0] in self.blacklist_domain:
            if is_request:
                self._log.warning(
                    "<= [%s] %s default response", flow.request.method, path
                )
                flow.response = self.default_response()
            else:
                self._log.warning(
                    "=> [%s] %s default response", flow.response.status_code, path
                )
                flow.response = self.default_response()
        else:
            if is_request:
                flow.metadata[FlowMeta.REQ_PASSTHROUGH] = True
            else:
                flow.metadata[FlowMeta.RESP_PASSTHROUGH] = True
            self._log.debug("%s %s passthrough", direction, path)

    # def websocket_start(self, flow: HTTPFlow):
    #     self._log.info("WebSocket connection started: %s", flow)
    #
    # def websocket_end(self, flow: HTTPFlow):
    #     self._log.info("WebSocket connection ended: %s", flow)

    def replace_route(
            self,
            host,
            path,
            new_handler,
            rtype=RouteType.REQUEST,
            method=HTTPVerb.ANY,
            allowed_statuses=None,
    ):
        """
        Replace an existing route if it matches the host and path.
        """
        routes = (
            self.request_routes if rtype == RouteType.REQUEST else self.response_routes
        )

        return routes.replace_route(host, path, new_handler, method, allowed_statuses)

        # partial_matches = []
        # for i, (h, parser, m, handler, status_codes) in enumerate(routes):
        #     if (
        #         h == host
        #         and (method in m or m in method)
        #         and parser.parse(path) is not None
        #     ):
        #         # routes[i] = (host, Parser(path), method, new_handler)
        #         # return True
        #         partial_matches.append([i, (h, parser, m, handler, status_codes)])
        #
        # if len(partial_matches) > 0:
        #     for i, (h, parser, m, handler, status_codes) in partial_matches:
        #         if method == m:
        #             routes[i] = (h, parser, m, new_handler, allowed_statuses)
        #             return True
        #         if method in m:
        #             m = m & ~method
        #             routes[i] = (h, parser, m, handler, status_codes)
        #         elif m in method:
        #             method = method & ~m
        #     routes.append((host, Parser(path), method, new_handler, allowed_statuses))
        #     return True
        #
        # return False

    def route(
            self,
            path: str,
            host: Optional[str] = None,
            rtype: RouteType = RouteType.REQUEST,
            method: Union[HTTPVerb, str, list[str]] = HTTPVerb.ANY,
            catch_error: bool = True,
            return_error: bool = False,
            allowed_statuses: Optional[List[int]] = None,
    ):
        """
        This is the main API used by end users.
        It decorates a view function to register it with given host and URL.

        Typical usage (taken from official example: `httpbin.py <https://github.com/xepor/xepor-examples/blob/main/httpbin/httpbin.py>`_):

        .. code-block:: python

            @api.route("/get")
            def change_your_request(flow: HTTPFlow):
                flow.request.query["payload"] = "evil_param"

            @api.route("/basic-auth/{usr}/{pwd}", rtype=RouteType.RESPONSE)
            def capture_auth(flow: HTTPFlow, usr=None, pwd=None):
                print(
                    f"auth @ {usr} + {pwd}:",
                    f"Captured {'successful' if flow.response.status_code < 300 else 'unsuccessful'} login:",
                    flow.request.headers.get("Authorization", ""),
                )

        See GitHub: `xepor/xepor-examples <https://github.com/xepor/xepor-examples>`_ for more examples.


        :param path: The URL path to be routed.
            The path definition grammar is similar to Python 3 :py:func:`str.format`.
            Check the documentation of ``parse`` library:
            `r1chardj0n3s/parse <https://github.com/r1chardj0n3s/parse>`_

        :param host: The host to be routed.
            This value will be matched against the following fields of
            incoming flow object by order:

            1. ``X-Forwarded-For`` Header. (only when `respect_proxy_headers` in :class:`InterceptedAPI` is `True`)
            2. HTTP ``Host`` Header, if exists.
            3.  ``flow.host`` reported by underlying layer.
                In HTTP or Socks proxy mode, it may hopefully be a hostname,
                otherwise, it'll be an IP address.

        :param rtype: Set the route be matched on either request or response.
            Accepting :class:`RouteType`.

        :param method: Sets the HTTP methods supported by the route.
            A bitmap created from :class:`HTTPVerb`.
            For convenience, if passed a string or list of strings, those will be converted to :class:`HTTPVerb`
            similarly to how Flask handles them.

        :param catch_error: If set to `True`, the exception inside the route
            will be handled by Xepor.

            If set to `False`, the exception will be raised and handled by mitmproxy.

        :param return_error: If set to `True`, the error message inside the exception
            (``str(exc)``) will be returned to client. This behaviour can be overritem
            through :func:`error_response`.

            If set to `False`, the exception will be printed to console,
            the ``flow`` object will be passed to mitmproxy continually.

            .. admonition:: Note

                When an exception occurred, the ``flow`` object does `not` always stay intact.
                This option is only a try-catch like normal Python code. If you run
                ``modify1(flow) and modify2(flow) and modify3(flow)`` and exception raised
                in ``modify2()``, the ``flow`` object will be modified partially.

        :param allowed_statuses: List of allowed status codes for the route. If the response status code
            is not in this list, the request will be logged.

        :return: The decorated function.
        """
        host = host or self.default_host

        if isinstance(method, str):
            method = HTTPVerb.parse_flags(method)
        elif isinstance(method, list):
            method = HTTPVerb.parse_list(method)

        def catcher(func: Callable):
            """
            The internal wrapper for catching exceptions
            if `catch_error` is specified.
            """

            @functools.wraps(func)
            def handler(flow: HTTPFlow, *args, **kwargs):
                try:
                    return func(flow, *args, **kwargs)
                except Exception as e:
                    etype, value, tback = sys.exc_info()
                    tb = "".join(traceback.format_exception(etype, value, tback))
                    self._log.error(
                        "Exception caught when handling response to %s:\n%s",
                        flow.request.pretty_url,
                        tb,
                    )
                    if return_error:
                        flow.response = self.error_response(str(e))

            return handler

        def wrapper(handler):
            if catch_error:
                handler = catcher(handler)

            # Check and replace existing route
            if self.replace_route(host, path, handler, rtype, method):
                self._log.info(
                    "Replaced existing route for host: %s, path: %s", host, path
                )
            else:
                if rtype == RouteType.REQUEST:
                    # self.request_routes.append(
                    #     (host, Parser(path), method, handler, None)
                    # )
                    self.request_routes.add_route(host, Parser(path), method, handler, None)
                elif rtype == RouteType.RESPONSE:
                    # self.response_routes.append(
                    #     (host, Parser(path), method, handler, allowed_statuses)
                    # )
                    self.response_routes.add_route(host, Parser(path), method, handler, allowed_statuses)
                else:
                    raise ValueError(f"Invalid route type: {rtype}")
            return handler

        return wrapper

    def ws_route(
            self,
            path=str,
            host: Optional[str] = None,
            rtype=RouteType.REQUEST,
            mtype=WSMsgType.ANY,
            catch_error: bool = True,
            return_error: bool = False,
    ):
        host = host or self.default_host

        def catcher(func: Callable) -> Callable:
            """
            The internal wrapper for catching exceptions
            if `catch_error` is specified.
            """

            @functools.wraps(func)
            def handler(flow: HTTPFlow, *args, **kwargs):
                try:
                    return func(flow, flow.websocket.messages[-1], *args, **kwargs)
                except Exception as e:
                    etype, value, tback = sys.exc_info()
                    tb = "".join(traceback.format_exception(etype, value, tback))
                    self._log.error(
                        "Exception caught when handling response to %s:\n%s",
                        flow.request.pretty_url,
                        tb,
                    )
                    if return_error:
                        flow.response = self.error_response(str(e))

            return handler

        def wrapper(handler: Callable):
            if catch_error:
                handler = catcher(handler)

            # Check and replace existing route
            if self.replace_ws_route(host, path, handler, rtype, mtype):
                self._log.info(
                    "Replaced existing route for host: %s, path: %s", host, path
                )
            else:
                if rtype == RouteType.REQUEST:
                    self.ws_request_routes.add_route(host, Parser(path), mtype, handler)
                elif rtype == RouteType.RESPONSE:
                    self.ws_response_routes.add_route(host, Parser(path), mtype, handler)
                else:
                    raise ValueError(f"Invalid route type: {rtype}")
            return handler

        return wrapper

    def remap_host(self, flow: HTTPFlow, overwrite=True):
        """
        Remaps the host of the flow to the destination host.

        .. admonition:: Note

            This function is used internally by Xepor.
            Refer to the source code for customization.

        :param flow: The flow to remap.
        :param overwrite: Whether to overwrite the host and port of the flow.
        :return: The remapped host.
        """
        host, port = self.get_host(flow)
        for src, dest in self.host_mapping:
            if (isinstance(src, re.Pattern) and src.match(host)) or (
                    isinstance(src, str) and host == src
            ):
                if overwrite and (
                        flow.request.host != dest or flow.request.port != port
                ):
                    if self.respect_proxy_headers:
                        flow.request.scheme = flow.request.headers["X-Forwarded-Proto"]
                    flow.server_conn = Server(address=(dest, port))
                    flow.request.host = dest
                    flow.request.port = port
                self._log.debug(
                    "flow: %s, remapping host: %s -> %s, port: %d",
                    flow,
                    host,
                    dest,
                    port,
                )
                return dest
        return host

    def get_host(self, flow: HTTPFlow) -> Tuple[str, int]:
        """
        Gets the host and port of the request.
        Extending from :py:attr:`mitmproxy.http.HTTPFlow.pretty_host` to accept
        values from proxy headers(``X-Forwarded-Host`` and ``X-Forwarded-Port``)

        .. admonition:: Note

            This function is used internally by Xepor.
            Refer to the source code for customization.

        :param flow: The HTTPFlow object.
        :return: A tuple of the host and port.
        """
        if FlowMeta.REQ_HOST not in flow.metadata:
            if self.respect_proxy_headers:
                # all(h in flow.request.headers for h in ["X-Forwarded-Host", "X-Forwarded-Port"])
                host = flow.request.headers["X-Forwarded-Host"]
                port = int(flow.request.headers["X-Forwarded-Port"])
            else:
                # Get Destination Host
                host, port = url.parse_authority(flow.request.pretty_host, check=False)
                port = port or url.default_port(flow.request.scheme) or 80
            flow.metadata[FlowMeta.REQ_HOST] = (host, port)
        return flow.metadata[FlowMeta.REQ_HOST]

    def default_response(self):
        """
        This is the default response function for Xepor.
        It will be called in following conditions:

        1. target host in HTTP request matches the ones in `blacklist_domain`.
        2. either `request_passthrough` or `response_passthrough` is set to `False`,
           and no route matches the incoming flow.

        Override this function if it suits your needs.

        :return: A Response object with status code 404
            and HTTP header ``X-Intercepted-By`` set to ``xepor``.
        """
        return Response.make(404, "Not Found", {"X-Intercepted-By": "xepor"})

    def error_response(self, msg: str = "APIServer Error"):
        """
        Returns a response with status code 502 and custom error message.

        Override this function if it suits your needs.

        :param msg: The message to be returned.

        :return: A Response object with status code 502
            and content set to the .
        """
        return Response.make(502, msg)

    def find_handler(self, host: str, path: str, rtype=RouteType.REQUEST, method=HTTPVerb.ANY):
        """
        Finds the appropriate handler for the request.

        .. admonition:: Note

            This function is used internally by Xepor.
            Refer to the source code for customization.

        :param host: The host of the request.
        :param path: The path of the request.
        :param rtype: The type of the route. Accepting :class:`RouteType`.
        :param method: The HTTP method of the route. Accepting :class:`HTTPVerb`
        :return: The handler and the parse result.
        """
        if rtype == RouteType.REQUEST:
            routes = self.request_routes
        elif rtype == RouteType.RESPONSE:
            routes = self.response_routes
        else:
            raise ValueError(f"Invalid route type: {rtype}")


        return routes.find_handler(host, path, method)
        # for h, parser, m, handler, status_codes in routes:
        #     if h != host or method not in m:
        #         continue
        #     parse_result = parser.parse(path)
        #     self._log.debug("Parse %s => %s", path, parse_result)
        #     if parse_result is not None:
        #         return handler, parse_result, status_codes
        #
        # return None, None, None

    def replace_ws_route(self, host, path, new_handler, rtype, mtype):
        routes = (
            self.ws_request_routes
            if rtype == RouteType.REQUEST
            else self.ws_response_routes
        )

        return routes.replace_route(host, path, new_handler, mtype)

    def find_ws_handler(self, host, path, rtype, mtype):
        if rtype == RouteType.REQUEST:
            routes = self.ws_request_routes
        elif rtype == RouteType.RESPONSE:
            routes = self.ws_response_routes
        else:
            raise ValueError(f"Invalid route type: {rtype}")

        return routes.find_handler(host, path, mtype)
        # for h, parser, m, handler in routes:
        #     if h != host or mtype not in m:
        #         continue
        #     parse_result = parser.parse(path)
        #     self._log.debug("Parse %s => %s", path, parse_result)
        #     if parse_result is not None:
        #         return handler, parse_result
        #
        # return None, None
