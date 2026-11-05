"""Optional tree-sitter AST layer: multi-language call graph + reachability.

This module is *additive and optional*. When ``tree_sitter_language_pack`` is
installed it parses source with real per-language grammars to build a
cross-file, unbounded-depth call graph and answer reachability questions
("which HTTP entry points reach this file?"). When tree-sitter is NOT installed
(e.g. a server image that has not been rebuilt yet) :data:`TREE_SITTER_AVAILABLE`
is ``False`` and callers fall back to the existing regex index — nothing breaks.

It intentionally resolves calls to definitions *by name* (an approximation, not
a precise inter-procedural CPG like Joern). That is still a large improvement
over the previous regex index, which only kept call edges for names unique to a
single file and walked them at the file level with depth 3. Here, name
resolution is AST-accurate (real definition/call nodes, not line-start regex),
spans files, and has no depth limit.
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field

LOG = logging.getLogger(__name__)

try:  # pragma: no cover - exercised by import environment, not unit logic
    from tree_sitter_language_pack import get_parser as _get_parser_impl

    TREE_SITTER_AVAILABLE = True
except Exception:  # noqa: BLE001 - any import/runtime error disables the layer
    _get_parser_impl = None
    TREE_SITTER_AVAILABLE = False


# Map the app's detected language label (LANGUAGE_BY_SUFFIX values) to the
# tree-sitter grammar name shipped by tree-sitter-language-pack.
GRAMMAR_BY_LANGUAGE: dict[str, str] = {
    "C": "c",
    "C++": "cpp",
    "C#": "csharp",
    "Go": "go",
    "Java": "java",
    "JavaScript": "javascript",
    "Kotlin": "kotlin",
    "PHP": "php",
    "Python": "python",
    "Ruby": "ruby",
    "Rust": "rust",
    "Scala": "scala",
    "TypeScript": "typescript",
    "Vue": "typescript",
}

# Node types that declare a callable, across the supported grammars.
_DEF_TYPES = {
    "function_definition",
    "function_declaration",
    "method_declaration",
    "method_definition",
    "constructor_declaration",
    "function_item",  # rust
    "method",  # ruby
    "singleton_method",  # ruby
    "func_literal",  # go
}

# Node types that invoke a callable, across the supported grammars.
_CALL_TYPES = {
    "call",  # python, ruby
    "call_expression",  # go, js/ts, rust, c/c++
    "method_invocation",  # java
    "function_call_expression",  # php
    "member_call_expression",  # php
    "scoped_call_expression",  # php
    "invocation_expression",  # c#
    "method_call",
}

# Over-generic names produce a hairball graph with no signal; drop them.
_NAME_STOPWORDS = frozenset(
    {
        "tostring", "hashcode", "equals", "get", "set", "size", "length",
        "print", "println", "printf", "log", "append", "add", "put", "new",
        "value", "valueof", "clone", "copy", "name", "len", "str", "int",
    }
)
_MIN_NAME_LEN = 3

# Safety caps so the optional pass cannot blow up on a huge monorepo.
MAX_AST_FILE_BYTES = 1_500_000
MAX_AST_FILES = 20_000


def _get_parser(grammar: str):
    return _get_parser_impl(grammar)


def _node_text(node) -> str:
    try:
        return node.text.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""


def _last_identifier(node) -> str | None:
    """Return the trailing identifier of a callee subtree.

    Handles ``obj.method`` / ``pkg.Func`` / ``a::b::c`` by taking the last
    identifier-like leaf, which is the method/function actually invoked.
    """
    if node is None:
        return None
    result: str | None = None
    stack = [node]
    # Depth-first, left-to-right, keeping the last identifier encountered.
    ordered: list = []
    while stack:
        current = stack.pop()
        ordered.append(current)
        stack.extend(reversed(current.children))
    for current in ordered:
        if current.type in {"identifier", "field_identifier", "name", "property_identifier"}:
            text = _node_text(current)
            if text:
                result = text
    return result


def _def_name(node) -> str | None:
    name_node = node.child_by_field_name("name")
    if name_node is not None:
        text = _node_text(name_node)
        if text:
            return text
    # C/C++: the name lives inside a declarator subtree.
    declarator = node.child_by_field_name("declarator")
    if declarator is not None:
        return _last_identifier(declarator)
    return None


def _call_name(node) -> str | None:
    for field_name in ("name", "function", "method", "callee"):
        child = node.child_by_field_name(field_name)
        if child is not None:
            name = _last_identifier(child)
            if name:
                return name
    # Fallback: first child is usually the callee expression.
    if node.children:
        return _last_identifier(node.children[0])
    return None


def _acceptable(name: str | None) -> bool:
    if not name or len(name) < _MIN_NAME_LEN:
        return False
    return name.lower() not in _NAME_STOPWORDS


@dataclass
class FileSymbols:
    path: str
    defined: set[str] = field(default_factory=set)
    called: set[str] = field(default_factory=set)


def file_symbols(path: str, text: str, language: str | None) -> FileSymbols | None:
    """Extract defined and called callable names from one file via tree-sitter.

    Returns ``None`` when tree-sitter is unavailable or the language is not
    supported, so the caller can skip the file cleanly.
    """
    if not TREE_SITTER_AVAILABLE or not language:
        return None
    grammar = GRAMMAR_BY_LANGUAGE.get(language)
    if grammar is None:
        return None
    try:
        parser = _get_parser(grammar)
        tree = parser.parse(text.encode("utf-8", "replace"))
    except Exception as exc:  # noqa: BLE001
        LOG.debug("tree-sitter parse failed for %s (%s): %s", path, grammar, exc)
        return None
    result = FileSymbols(path=path)
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        node_type = node.type
        if node_type in _DEF_TYPES:
            name = _def_name(node)
            if _acceptable(name):
                result.defined.add(name)
        elif node_type in _CALL_TYPES:
            name = _call_name(node)
            if _acceptable(name):
                result.called.add(name)
        stack.extend(node.children)
    return result


@dataclass
class RouteReach:
    """How an HTTP entry point reaches a file through the call graph.

    ``route`` is the reaching entry's label (e.g. ``"GET /user"``),
    ``entry_path`` the file that entry lives in, and ``chain`` the file-level
    call path ``[entry_path, ..., path]`` reconstructed from BFS parent links.
    The chain is an approximation (calls resolved by name), not a precise
    inter-procedural path, and is used as human/AI-readable candidate evidence.
    """

    route: str
    entry_path: str
    chain: list[str] = field(default_factory=list)


@dataclass
class CallGraph:
    """File-level call graph derived from AST definitions/calls.

    An edge ``P -> Q`` means a callable invoked in file ``P`` is defined in file
    ``Q`` (``Q != P``). Reachability is computed over these edges.
    """

    forward: dict[str, set[str]] = field(default_factory=dict)
    backward: dict[str, set[str]] = field(default_factory=dict)
    paths: set[str] = field(default_factory=set)

    def reachable_from(self, seeds: set[str]) -> set[str]:
        return self._bfs(seeds, self.forward)

    def can_reach(self, targets: set[str]) -> set[str]:
        """Paths that can reach any target (BFS over reversed edges)."""
        return self._bfs(targets, self.backward)

    def _bfs(self, seeds: set[str], edges: dict[str, set[str]]) -> set[str]:
        seen: set[str] = set()
        queue: deque[str] = deque(seed for seed in seeds if seed in self.paths)
        seen.update(queue)
        while queue:
            node = queue.popleft()
            for nxt in edges.get(node, ()):  # noqa: SIM113
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)
        return seen

    def route_reach_from(self, seed_routes: dict[str, str]) -> dict[str, RouteReach]:
        """Entry-point reachability with the reaching route, entry file and chain.

        Multi-source forward BFS seeded with ``{entrypoint_path: route_label}``;
        the first entry to reach a path wins (BFS order). Parent back-links let
        us reconstruct the file-level call chain from the entry to each reached
        path. Used to attach an HTTP entry point to a cross-file sink (e.g. a
        DAO) that has no entry point in its own file, so layered
        Controller->Service->DAO sinks are tied back to the real attack surface
        *and* carry the chain that connects them as evidence.
        """
        label: dict[str, str] = {}
        origin: dict[str, str] = {}
        parent: dict[str, str | None] = {}
        queue: deque[str] = deque()
        for seed_path, route in seed_routes.items():
            if seed_path in self.paths and seed_path not in label:
                label[seed_path] = route
                origin[seed_path] = seed_path
                parent[seed_path] = None
                queue.append(seed_path)
        while queue:
            node = queue.popleft()
            for nxt in self.forward.get(node, ()):  # noqa: SIM113
                if nxt not in label:
                    label[nxt] = label[node]
                    origin[nxt] = origin[node]
                    parent[nxt] = node
                    queue.append(nxt)
        reach: dict[str, RouteReach] = {}
        for path in label:
            chain: list[str] = []
            cursor: str | None = path
            while cursor is not None:
                chain.append(cursor)
                cursor = parent[cursor]
            chain.reverse()
            reach[path] = RouteReach(route=label[path], entry_path=origin[path], chain=chain)
        return reach

    def route_labels_from(self, seed_routes: dict[str, str]) -> dict[str, str]:
        """Reachable-file -> reaching-route label map.

        Thin wrapper over :meth:`route_reach_from` for callers that only need
        the route label and not the chain.
        """
        return {path: reach.route for path, reach in self.route_reach_from(seed_routes).items()}


def build_call_graph(files: list[tuple[str, str, str | None]]) -> CallGraph | None:
    """Build a file-level call graph from ``(path, text, language)`` tuples.

    Returns ``None`` when tree-sitter is unavailable so callers fall back to the
    regex index. Honors :data:`MAX_AST_FILES` / :data:`MAX_AST_FILE_BYTES`.
    """
    if not TREE_SITTER_AVAILABLE:
        return None
    symbols: list[FileSymbols] = []
    name_to_paths: dict[str, set[str]] = {}
    analyzed = 0
    for path, text, language in files:
        if analyzed >= MAX_AST_FILES:
            break
        if text is None or len(text) > MAX_AST_FILE_BYTES:
            continue
        info = file_symbols(path, text, language)
        if info is None:
            continue
        analyzed += 1
        symbols.append(info)
        for name in info.defined:
            name_to_paths.setdefault(name, set()).add(path)

    graph = CallGraph()
    for info in symbols:
        graph.paths.add(info.path)
    for info in symbols:
        for name in info.called:
            for target_path in name_to_paths.get(name, ()):  # noqa: SIM113
                if target_path == info.path:
                    continue
                graph.forward.setdefault(info.path, set()).add(target_path)
                graph.backward.setdefault(target_path, set()).add(info.path)
    return graph
