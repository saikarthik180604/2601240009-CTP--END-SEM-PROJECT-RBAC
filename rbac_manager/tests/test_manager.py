"""Tests: users, role assignment, permission checking, audit logging, stats."""

import pytest

from rbac import (
    DuplicateEntityError,
    PermissionDeniedError,
    PermissionNotFoundError,
    RoleNotFoundError,
    UserNotFoundError,
    ValidationError,
)


# ------------------------------------------------------------------ users
def test_create_user_and_home_tenant_membership(manager):
    tenant = manager.create_tenant("ACME")
    user = manager.create_user("Alice", "alice@acme.com", tenant.tenant_id)
    assert user.username == "Alice"
    assert user.email == "alice@acme.com"
    assert user.belongs_to_tenant(tenant.tenant_id)
    assert user.roles == []


def test_duplicate_username_rejected(manager):
    tenant = manager.create_tenant("ACME")
    manager.create_user("Alice", "a@acme.com", tenant.tenant_id)
    with pytest.raises(DuplicateEntityError):
        manager.create_user("Alice", "other@acme.com", tenant.tenant_id)


def test_invalid_email_rejected(manager):
    tenant = manager.create_tenant("ACME")
    with pytest.raises(ValidationError):
        manager.create_user("Alice", "not-an-email", tenant.tenant_id)


def test_user_can_join_several_tenants(demo):
    user = demo.m.get_user(demo.carol)
    assert user.belongs_to_tenant(demo.acme) and user.belongs_to_tenant(demo.globex)


# ------------------------------------------------------- role assignment
def test_assign_and_remove_role(demo):
    m = demo.m
    m.assign_role(demo.bob, demo.acme_roles["Editor"])
    assert m.check_permission(demo.bob, demo.acme, "products:create") == "ALLOW"
    m.remove_role(demo.bob, demo.acme_roles["Editor"])
    assert m.check_permission(demo.bob, demo.acme, "products:create") == "DENY"


def test_assigning_same_role_twice_is_harmless(demo):
    m = demo.m
    m.assign_role(demo.bob, demo.acme_roles["Viewer"])
    assert m.get_user(demo.bob).roles.count(demo.acme_roles["Viewer"]) == 1


def test_remove_role_user_does_not_have(demo):
    with pytest.raises(RoleNotFoundError):
        demo.m.remove_role(demo.bob, demo.acme_roles["Admin"])


# ------------------------------------------------------ permission checks
def test_check_permission_returns_exact_strings(demo):
    assert demo.m.check_permission(demo.alice, demo.acme, "users:create") == "ALLOW"
    assert demo.m.check_permission(demo.bob, demo.acme, "users:delete") == "DENY"


def test_unknown_user_is_denied_and_enforce_raises(demo):
    assert demo.m.check_permission(999, demo.acme, "users:create") == "DENY"
    with pytest.raises(UserNotFoundError):
        demo.m.enforce(999, demo.acme, "users:create")


def test_unknown_permission_is_denied(demo):
    assert demo.m.check_permission(demo.alice, demo.acme, "rockets:launch") == "DENY"
    with pytest.raises(PermissionNotFoundError):
        demo.m.enforce(demo.alice, demo.acme, "rockets:launch")


def test_enforce_returns_on_allow_and_raises_on_deny(demo):
    assert demo.m.enforce(demo.alice, demo.acme, "users:create")["result"] == "ALLOW"
    with pytest.raises(PermissionDeniedError):
        demo.m.enforce(demo.alice, demo.acme, "billing:delete")


def test_effective_permissions_lists_sources_and_denials(demo):
    info = demo.m.get_effective_permissions(demo.alice, demo.acme)
    by_name = {item["permission"]: item for item in info["allowed"]}
    assert by_name["dashboard:view"]["source_role"] == "Viewer"
    assert by_name["dashboard:view"]["inherited"] is True
    assert by_name["billing:edit"]["source_role"] == "Admin"
    assert "billing:delete" not in by_name
    assert info["denied"] == ["billing:delete"]


# ------------------------------------------------------------ audit log
def test_every_check_is_audited(demo):
    m = demo.m
    before = m.audit.stats()["total"]
    m.check_permission(demo.alice, demo.acme, "users:create")
    m.check_permission(demo.bob, demo.acme, "users:delete")
    assert m.audit.stats()["total"] == before + 2


def test_audit_entry_contains_all_fields(demo):
    demo.m.check_permission(demo.alice, demo.acme, "billing:delete")
    entry = demo.m.audit.list_entries(limit=1)[0]
    assert entry.username == "Alice"
    assert entry.tenant == "ACME"
    assert entry.permission == "billing:delete"
    assert entry.result == "DENY"
    assert entry.reason == "Explicit deny rule"
    assert entry.timestamp
    assert entry.format() == "Alice | ACME | billing:delete | DENY | Explicit deny rule"


def test_audit_records_failed_checks_for_unknown_user(demo):
    demo.m.check_permission(999, demo.acme, "users:create")
    entry = demo.m.audit.list_entries(limit=1)[0]
    assert entry.result == "DENY"
    assert "not found" in entry.reason


def test_audit_filter_and_stats(demo):
    m = demo.m
    m.check_permission(demo.alice, demo.acme, "users:create")   # ALLOW
    m.check_permission(demo.bob, demo.acme, "users:delete")     # DENY
    assert {e.result for e in m.audit.list_entries(result="ALLOW")} == {"ALLOW"}
    assert {e.result for e in m.audit.list_entries(result="DENY")} == {"DENY"}
    stats = m.audit.stats()
    assert stats["allowed"] == 1 and stats["denied"] == 1 and stats["total"] == 2


def test_stats_counts_everything(demo):
    stats = demo.m.stats()
    assert stats["tenants"] == 2
    assert stats["users"] == 4
    assert stats["roles"] == 8
    assert stats["permissions"] == 17
