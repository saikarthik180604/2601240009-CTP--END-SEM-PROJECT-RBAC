"""Tests: role graph, traversal, cycle detection and inheritance."""

import pytest

from rbac import CircularRoleError, RoleGraph, TenantAccessDeniedError


def chain_graph():
    """Viewer(1) -> Editor(2) -> Manager(3) -> Admin(4)"""
    graph = RoleGraph()
    graph.add_edge(1, 2)
    graph.add_edge(2, 3)
    graph.add_edge(3, 4)
    return graph


def test_chain_viewer_editor_manager_admin_is_valid():
    graph = chain_graph()
    assert graph.edges() == [(1, 2), (2, 3), (3, 4)]
    assert not graph.has_cycle()


def test_bfs_traversal_order_goes_from_senior_to_base_roles():
    assert chain_graph().traverse_inherited([4]) == [4, 3, 2, 1]


def test_ancestors_and_descendants():
    graph = chain_graph()
    assert graph.ancestors(4) == [3, 2, 1]
    assert graph.ancestors(1) == []
    assert graph.descendants(1) == [2, 3, 4]


def test_has_path_dfs():
    graph = chain_graph()
    assert graph.has_path(1, 4)
    assert not graph.has_path(4, 1)


def test_cycle_detection_rejects_closing_edge():
    graph = chain_graph()
    with pytest.raises(CircularRoleError):
        graph.add_edge(4, 1)          # Admin -> Viewer closes the loop
    assert not graph.has_edge(4, 1)   # the bad edge was NOT stored


def test_self_loop_is_a_cycle():
    graph = RoleGraph()
    graph.add_role(1)
    with pytest.raises(CircularRoleError):
        graph.add_edge(1, 1)


def test_two_node_cycle_rejected():
    graph = RoleGraph()
    graph.add_edge(1, 2)
    with pytest.raises(CircularRoleError):
        graph.add_edge(2, 1)


def test_diamond_hierarchy_visits_each_role_once():
    graph = RoleGraph()
    graph.add_edge(1, 2)
    graph.add_edge(1, 3)
    graph.add_edge(2, 4)
    graph.add_edge(3, 4)
    order = graph.traverse_inherited([4])
    assert sorted(order) == [1, 2, 3, 4]
    assert len(order) == 4


def test_remove_edge_breaks_inheritance():
    graph = chain_graph()
    graph.remove_edge(2, 3)
    assert graph.ancestors(4) == [3]


def test_manager_rejects_admin_to_viewer_cycle(demo):
    viewer, admin = demo.acme_roles["Viewer"], demo.acme_roles["Admin"]
    with pytest.raises(CircularRoleError):
        demo.m.add_role_parent(child_role_id=viewer, parent_role_id=admin)
    assert demo.m.get_role(viewer).parent_roles == []   # nothing was written


def test_manager_rejects_cross_tenant_inheritance(demo):
    with pytest.raises(TenantAccessDeniedError):
        demo.m.add_role_parent(demo.globex_roles["Admin"], demo.acme_roles["Viewer"])


def test_seeded_hierarchy_is_acyclic(demo):
    assert not demo.m.build_graph().has_cycle()


def test_get_hierarchy_describes_nodes_and_edges(demo):
    data = demo.m.get_hierarchy(demo.acme)
    assert len(data["nodes"]) == 4
    assert len(data["edges"]) == 3
    admin = next(n for n in data["nodes"] if n["role_name"] == "Admin")
    assert admin["parents"] == [demo.acme_roles["Manager"]]


def test_permissions_inherit_down_the_chain(demo):
    m = demo.m
    assert m.check_permission(demo.alice, demo.acme, "dashboard:view") == "ALLOW"   # Viewer
    assert m.check_permission(demo.alice, demo.acme, "products:create") == "ALLOW"  # Editor
    assert m.check_permission(demo.alice, demo.acme, "products:update") == "ALLOW"  # Manager
    assert m.check_permission(demo.alice, demo.acme, "products:delete") == "ALLOW"  # Admin


def test_carol_inherits_viewer_through_editor_but_not_manager(demo):
    m = demo.m
    assert m.check_permission(demo.carol, demo.acme, "products:read") == "ALLOW"
    assert m.check_permission(demo.carol, demo.acme, "products:update") == "DENY"


def test_inheritance_does_not_flow_upwards(demo):
    # Bob (Viewer) must not get Editor's products:create
    assert demo.m.check_permission(demo.bob, demo.acme, "products:create") == "DENY"
