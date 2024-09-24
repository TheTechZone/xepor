from typing import Optional, List, Callable, Tuple

from src.xepor import HTTPVerb, HandlerType

import functools
from parse import Parser  # noqa

class TrieNode:
    def __init__(self):
        self.children: dict[str, TrieNode] = {}
        self.handlers = {}


wildcardPattern = "{*}"


class Trie:
    def __init__(self):
        self.root = TrieNode()

    def insert(self, host: str, path_segments: List[str], handler: HandlerType, parser: Parser, http_verb: HTTPVerb, allowed_statues: Optional[List[int]]):
        """Inserts a new route into the Trie"""
        node = self.root
        for segment in path_segments:
            if segment not in node.children:
                node.children[segment] = TrieNode()
            node = node.children[segment]
        node.handlers[http_verb] = (handler, parser)

    def replace(self, host: str, path_segments: List[str], new_handler: HandlerType, parser: Parser, http_verb: HTTPVerb, allowed_statues: Optional[List[int]]) -> bool:
        node = self.root
        for segment in path_segments:
            if segment not in node.children:
                return False
            node = node.children[segment]
        if http_verb in node.handlers:
            node.handlers[http_verb] = (new_handler, parser)
        return True

    def find(self, host: str, path_segments: List[str], http_verb) -> Tuple[Optional[HandlerType], Optional[dict]]:
        node = self.root
        params = {}
        for segment in path_segments:
            if segment not in node.children and wildcardPattern in node.children:
                segment = wildcardPattern
            if segment not in node.children:
                return None, None
            node = node.children[segment]
            if segment == wildcardPattern:
                parse_res = node.handlers[http_verb][1].parse("/" + "/".join(path_segments))
                if parse_res is not None:
                    params.update(parse_res.named)
        handler, _ = node.handlers.get(http_verb, (None, None))
        return handler, params


class Router:
    def __init__(self):
        self.routes = Trie()

    @staticmethod
    def _split_to_segments(path: Parser) -> list[str]:
        segments = path.format.split('/')
        return [wildcardPattern if '{' in segment and '}' in segment else segment for segment in segments][1:]

    def add_route(self, host: str, path: Parser, method: HTTPVerb, handler: HandlerType, allowed_statuses: Optional[List[int]] = None):
        path_segments = self._split_to_segments(path)
        self.routes.insert(host, path_segments, handler, path, method, allowed_statuses)

    def replace_route(self, host: str, path: Parser, method: HTTPVerb, new_handler: HandlerType, allowed_statuses: Optional[List[int]] = None) -> bool:
        path_segments = self._split_to_segments(path)
        return self.routes.replace(host, path_segments, new_handler, path, method, allowed_statuses)

    def find_handler(self, host: str, path: str, method=HTTPVerb.ANY) -> Tuple[
        Optional[HandlerType], Optional[dict], None]:
        handler, params = self.routes.find(host, path.split('/')[1:], method)
        if handler:
            return handler, params, None
        return None, None, None

    def print_routes(self):
        def print_trie(node: TrieNode, path=''):
            if node.handlers:
                print(f'Path: {path}, Leaf Handler(s): {node.handlers}')
            for key, child in node.children.items():
                print_trie(child, path + '/' + key)

        print_trie(self.routes.root)


if __name__ == '__main__':
    r = Router()
    r.add_route("pets.com", Parser("/api/{pet_type}/{name}"), HTTPVerb.GET, lambda: "1")
    r.add_route("pets.com", Parser("/api/{pet_type}/{name}"), HTTPVerb.POST, lambda: "2")
    r.add_route("pets.com", Parser("/api/kittens/{action}"), HTTPVerb.ANY, lambda x: f"You tried to {x.get('action')} a kitty!")

    r.add_route("pets.com", Parser("/api/kittens/info"), HTTPVerb.ANY, lambda: "3")
    r.add_route("pets.com", Parser("/api/kittens/info"), HTTPVerb.ANY, lambda: "meow meow")

    print(r)
    r.print_routes()
    f, params, _ = r.find_handler("pets.com", "/api/kittens/cuddle")
    if f:
        print(_ := f(params), params)

    f, params, _ = r.find_handler("pets.com", "/api/kittens/info", method=HTTPVerb.GET)
    if f:
        print(_ := f(), params)
