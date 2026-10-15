"""Tests: permission objects and the greedy resolver."""

import pytest

from rbac import DuplicateEntityError, GreedyPermissionResolver, Permission, RoleGraph, ValidationError


def test_permission_object_parses_resource_and_action():
    permission = Permission(1, "users:create", "Create users")
    assert permission.resource == "users"
    assert permission.action == "create"
    assert permission.to_dict()["name"] == "users:create"


@pytest.mark.parametrize("bad_name", ["users", "Users:Create", "users:", ":create", "a b:c", ""])
def test_invalid_permission_name_rejected(bad_name):
    with pytest.raises(ValidationError):
        Permission(None, bad_name)


def test_create_permission(manager):
    created = manager.create_permission("invoices:approve", "Approve invoices")
    assert created.permission_id is not None
    assert manager.get_permission_by_name("invoices:approve").description == "Approve invoices"


def test_duplicate_permission_rejected(manager):
    manager.create_permission("users:read")
    with pytest.raises(DuplicateEntityError):
        manager.create_permission("users:read")


def test_seed_creates_all_required_permissions(demo):
    names = {p.name for p in demo.m.list_permissions()}
    required = {
        "users:create", "users:read", "users:update", "users:delete",
        "roles:create", "roles:read", "roles:update", "roles:delete",
        "products:create", "products:read", "products:update", "products:delete",
        "reports:view", "billing:view", "billing:edit", "billing:delete", "dashboard:view",
    }
    assert required <= names


def test_greedy_resolver_collects_inherited_permissions():
    graph = RoleGraph()
    graph.add_edge(1, 2)   # role 2 inherits role 1
    graph.add_edge(2, 3)   # role 3 inherits role 2
    role_permissions = {1: {"a:read"}, 2: {"a:write"}, 3: {"a:delete"}}
    resolved = GreedyPermissionResolver().resolve(graph, [3], role_permissions)
    assert set(resolved.granted) == {"a:read", "a:write", "a:delete"}


def test_greedy_resolver_removes_duplicates_nearest_role_wins():
    graph = RoleGraph()
    graph.add_edge(1, 2)
    role_permissions = {1: {"a:read"}, 2: {"a:read", "a:write"}}
    resolved = GreedyPermissionResolver().resolve(graph, [2], role_permissions)
    assert resolved.source_of("a:read") == 2     # claimed by the assigned role first
    assert len(resolved.granted) == 2


def test_greedy_resolver_explicit_deny_beats_allow():
    graph = RoleGraph()
    graph.add_role(1)
    resolved = GreedyPermissionResolver().resolve(graph, [1], {1: {"a:read", "a:write"}}, {"a:write"})
    assert resolved.is_allowed("a:read")
    assert not resolved.is_allowed("a:write")
    assert resolved.is_denied("a:write")
    assert "a:write" not in resolved.effective


def test_greedy_resolver_with_no_roles_grants_nothing():
    resolved = GreedyPermissionResolver().resolve(RoleGraph(), [], {})
    assert resolved.granted == {}
