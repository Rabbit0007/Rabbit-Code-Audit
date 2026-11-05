"""Tests for the optional tree-sitter AST call-graph layer.

Skipped automatically when tree-sitter is not installed, so a minimal image
that has not been rebuilt still runs the rest of the suite cleanly.
"""

from __future__ import annotations

import pytest

from cairn.server import ast_index
from cairn.server.ast_index import TREE_SITTER_AVAILABLE, build_call_graph, file_symbols

pytestmark = pytest.mark.skipif(
    not TREE_SITTER_AVAILABLE, reason="tree-sitter not installed in this environment"
)


def test_file_symbols_java_defs_and_calls():
    text = """
public class UserService {
    public User findUser(String id) {
        return userDao.queryUser(id);
    }
}
"""
    info = file_symbols("svc/UserService.java", text, "Java")
    assert info is not None
    assert "findUser" in info.defined
    assert "queryUser" in info.called


def test_file_symbols_go_defs_and_calls():
    text = """
func handleUser(c *gin.Context) {
    id := c.Query("id")
    findUser(id)
}
func findUser(id string) {}
"""
    info = file_symbols("svc/user.go", text, "Go")
    assert info is not None
    assert "handleUser" in info.defined
    assert "findUser" in info.defined
    assert "findUser" in info.called


def test_cross_file_reachability_controller_service_dao():
    # Classic layered app: Controller -> Service -> DAO, each in its own file.
    controller = (
        "controller/UserController.java",
        """
public class UserController {
    @GetMapping("/user")
    public User handleUser(@RequestParam String id) {
        return userService.findUser(id);
    }
}
""",
        "Java",
    )
    service = (
        "service/UserService.java",
        """
public class UserService {
    public User findUser(String id) {
        return userDao.queryUser(id);
    }
}
""",
        "Java",
    )
    dao = (
        "dao/UserDao.java",
        """
public class UserDao {
    public User queryUser(String id) {
        return jdbc.execute("SELECT * FROM users WHERE id=" + id);
    }
}
""",
        "Java",
    )

    graph = build_call_graph([controller, service, dao])
    assert graph is not None

    reachable = graph.reachable_from({controller[0]})
    # The DAO (where the SQL sink lives) is reachable from the HTTP entry point
    # even though input and sink are in different files.
    assert dao[0] in reachable
    assert service[0] in reachable

    reaching = graph.can_reach({dao[0]})
    # Backward: the controller is an entry point that reaches the DAO sink.
    assert controller[0] in reaching
    assert service[0] in reaching


def test_build_call_graph_without_tree_sitter(monkeypatch):
    # When tree-sitter is unavailable the builder must return None (fallback),
    # never raise.
    monkeypatch.setattr(ast_index, "TREE_SITTER_AVAILABLE", False)
    assert build_call_graph([("a.go", "func f(){}", "Go")]) is None
    assert file_symbols("a.go", "func f(){}", "Go") is None


def test_ast_entry_routes_ties_cross_file_dao_sink_to_controller(tmp_path):
    # End-to-end for the source_service integration helper: a DAO sink file with
    # no HTTP input of its own is tied back to the Controller route that reaches
    # it through the Service layer.
    from types import SimpleNamespace

    from cairn.server.source_service import _ast_entry_routes

    sources = {
        "controller/UserController.java": """
public class UserController {
    public User handleUser(String id) {
        return userService.findUser(id);
    }
}
""",
        "service/UserService.java": """
public class UserService {
    public User findUser(String id) {
        return userDao.queryUser(id);
    }
}
""",
        "dao/UserDao.java": """
public class UserDao {
    public User queryUser(String id) {
        return jdbc.execute("SELECT * FROM users WHERE id=" + id);
    }
}
""",
    }
    files = []
    for rel, body in sources.items():
        abs_path = tmp_path / rel
        abs_path.parent.mkdir(parents=True, exist_ok=True)
        abs_path.write_text(body, encoding="utf-8")
        files.append(SimpleNamespace(path=rel, is_binary=False, language="Java"))

    routes = _ast_entry_routes(
        files, tmp_path, {"controller/UserController.java": "GET /user"}
    )
    assert routes.get("dao/UserDao.java") == "GET /user"
    assert routes.get("service/UserService.java") == "GET /user"


def test_route_reach_from_builds_chain():
    # route_reach_from returns, for each reachable file, the reaching route, the
    # entry file, and the ordered file-level call chain entry -> ... -> file.
    controller = (
        "controller/UserController.java",
        """
public class UserController {
    public User handleUser(String id) {
        return userService.findUser(id);
    }
}
""",
        "Java",
    )
    service = (
        "service/UserService.java",
        """
public class UserService {
    public User findUser(String id) {
        return userDao.queryUser(id);
    }
}
""",
        "Java",
    )
    dao = (
        "dao/UserDao.java",
        """
public class UserDao {
    public User queryUser(String id) {
        return jdbc.execute("SELECT * FROM users WHERE id=" + id);
    }
}
""",
        "Java",
    )

    graph = build_call_graph([controller, service, dao])
    assert graph is not None

    reach = graph.route_reach_from({controller[0]: "GET /user"})
    dao_reach = reach.get(dao[0])
    assert dao_reach is not None
    assert dao_reach.route == "GET /user"
    assert dao_reach.entry_path == controller[0]
    # The chain starts at the entry point and ends at the sink file, in order.
    assert dao_reach.chain[0] == controller[0]
    assert dao_reach.chain[-1] == dao[0]
    assert service[0] in dao_reach.chain
    # route_labels_from stays consistent with the richer reach map.
    labels = graph.route_labels_from({controller[0]: "GET /user"})
    assert labels[dao[0]] == "GET /user"


def test_ast_call_chain_evidence_renders_cross_file_chain():
    # The evidence renderer turns a cross-file RouteReach into a readable note,
    # and returns None for same-file / missing reach so behaviour is unchanged
    # when there is no genuine cross-file path.
    from cairn.server.ast_index import RouteReach
    from cairn.server.source_service import _ast_call_chain_evidence

    reach = RouteReach(
        route="GET /user",
        entry_path="controller/UserController.java",
        chain=[
            "controller/UserController.java",
            "service/UserService.java",
            "dao/UserDao.java",
        ],
    )
    evidence = _ast_call_chain_evidence(reach, "dao/UserDao.java", 5, "数据库执行能力")
    assert evidence is not None
    assert "GET /user" in evidence
    assert "controller/UserController.java" in evidence
    assert "dao/UserDao.java:5" in evidence
    assert "数据库执行能力" in evidence

    # No reach -> no evidence.
    assert _ast_call_chain_evidence(None, "dao/UserDao.java", 5, "x") is None
    # Single-file chain is not a cross-file flow -> no evidence.
    assert (
        _ast_call_chain_evidence(
            RouteReach(route="r", entry_path="a.java", chain=["a.java"]), "a.java", 1, "x"
        )
        is None
    )
