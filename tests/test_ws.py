import pytest
from mitmproxy.http import HTTPFlow, Response
from mitmproxy.test import taddons, tflow
from mitmproxy.websocket import WebSocketMessage

from src.xepor import InterceptedAPI, HTTPVerb


@pytest.fixture
def api_simple():
    api = InterceptedAPI("example.org")

    @api.ws_route("/messages")
    def route(flow: HTTPFlow, message: WebSocketMessage):
        # flow.response = Response.make(200, "healthy")
        message.content = b"Meow :3"

    return api


def test_ws(toptions, api_simple):
    with taddons.context(api_simple, options=toptions) as tctx:
        flow = tflow.tflow()
        flow.request.url = "wss://example.org/messages"
        flow.websocket = tflow.twebsocket(messages=False)

        # Simulate a WebSocket message
        flow.websocket.messages.append(WebSocketMessage(1, True, b"other_data"))
        api_simple.websocket_message(flow)

        assert len(flow.websocket.messages) == 1
        assert flow.websocket.messages[-1].content == b"Meow :3"
