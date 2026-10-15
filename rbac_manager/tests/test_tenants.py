"""Tests: strict tenant isolation."""

import pytest

from rbac import TenantAccessDeniedError, TenantNotFoundError


def test_acme_user_cannot_access_globex(demo):
    result = demo.m.check_permission_detailed(demo.bob, demo.globex, "products:read")
    assert result["result"] == "DENY"
    assert "tenant isolation" in result["reason"]


def test_acme_admin_has_no_power_in_globex(demo):
    assert demo.m.check_permission(demo.alice, demo.globex, "users:create") == "DENY"


def test_globex_admin_works_in_globex_but_not_acme(demo):
    assert demo.m.check_permission(demo.dave, demo.globex, "users:create") == "ALLOW"
    assert demo.m.check_permission(demo.dave, demo.acme, "users:create") == "DENY"


def test_roles_are_scoped_per_tenant_for_multi_tenant_user(demo):
    m = demo.m
    # Carol: Editor in ACME, Viewer in GLOBEX
    assert m.check_permission(demo.carol, demo.acme, "products:create") == "ALLOW"
    assert m.check_permission(demo.carol, demo.globex, "products:create") == "DENY"
    assert m.check_permission(demo.carol, demo.globex, "products:read") == "ALLOW"


def test_membership_alone_does_not_grant_access(demo):
    m = demo.m
    m.add_user_to_tenant(demo.alice, demo.globex)    # Alice joins GLOBEX but has no GLOBEX role
    result = m.check_permission_detailed(demo.alice, demo.globex, "users:create")
    assert result["result"] == "DENY"
    assert "no role" in result["reason"]


def test_cannot_assign_role_of_a_tenant_user_does_not_belong_to(demo):
    with pytest.raises(TenantAccessDeniedError):
        demo.m.assign_role(demo.bob, demo.globex_roles["Admin"])


def test_enforce_raises_for_cross_tenant_access(demo):
    with pytest.raises(TenantAccessDeniedError):
        demo.m.enforce(demo.bob, demo.globex, "products:read")


def test_unknown_tenant_is_denied_and_enforce_raises(demo):
    assert demo.m.check_permission(demo.alice, 999, "users:create") == "DENY"
    with pytest.raises(TenantNotFoundError):
        demo.m.enforce(demo.alice, 999, "users:create")


def test_list_users_by_tenant(demo):
    acme_names = {u.username for u in demo.m.list_users(demo.acme)}
    globex_names = {u.username for u in demo.m.list_users(demo.globex)}
    assert acme_names == {"Alice", "Bob", "Carol"}
    assert globex_names == {"Dave", "Carol"}
