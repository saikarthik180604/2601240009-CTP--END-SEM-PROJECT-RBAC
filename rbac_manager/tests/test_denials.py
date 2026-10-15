"""Tests: explicit deny and default deny."""

from rbac import TenantAccessDeniedError
import pytest


def test_explicit_deny_overrides_inherited_allow(demo):
    # Admin role allows billing:delete, but Alice has an explicit deny.
    assert demo.m.check_permission(demo.alice, demo.acme, "billing:delete") == "DENY"


def test_explicit_deny_reason_is_reported(demo):
    result = demo.m.check_permission_detailed(demo.alice, demo.acme, "billing:delete")
    assert result["reason"] == "Explicit deny rule"


def test_explicit_deny_only_affects_that_permission(demo):
    assert demo.m.check_permission(demo.alice, demo.acme, "billing:edit") == "ALLOW"


def test_explicit_deny_only_affects_that_user(demo):
    m = demo.m
    eve = m.create_user("Eve", "eve@acme.com", demo.acme)
    m.assign_role(eve.user_id, demo.acme_roles["Admin"])
    assert m.check_permission(eve.user_id, demo.acme, "billing:delete") == "ALLOW"


def test_removing_explicit_deny_restores_allow(demo):
    demo.m.remove_explicit_deny(demo.alice, demo.acme, "billing:delete")
    assert demo.m.check_permission(demo.alice, demo.acme, "billing:delete") == "ALLOW"


def test_new_explicit_deny_overrides_directly_assigned_permission(demo):
    m = demo.m
    assert m.check_permission(demo.bob, demo.acme, "products:read") == "ALLOW"
    m.add_explicit_deny(demo.bob, demo.acme, "products:read")
    assert m.check_permission(demo.bob, demo.acme, "products:read") == "DENY"


def test_explicit_deny_is_limited_to_its_tenant(demo):
    m = demo.m
    # Carol is a Viewer in GLOBEX. Deny it in ACME only.
    m.add_explicit_deny(demo.carol, demo.acme, "products:read")
    assert m.check_permission(demo.carol, demo.acme, "products:read") == "DENY"
    assert m.check_permission(demo.carol, demo.globex, "products:read") == "ALLOW"


def test_cannot_add_deny_for_tenant_user_does_not_belong_to(demo):
    with pytest.raises(TenantAccessDeniedError):
        demo.m.add_explicit_deny(demo.bob, demo.globex, "products:read")


def test_default_deny_when_no_rule_matches(demo):
    result = demo.m.check_permission_detailed(demo.bob, demo.acme, "users:delete")
    assert result["result"] == "DENY"
    assert "default deny" in result["reason"]


def test_default_deny_for_member_without_roles(demo):
    m = demo.m
    frank = m.create_user("Frank", "frank@acme.com", demo.acme)   # no role assigned
    result = m.check_permission_detailed(frank.user_id, demo.acme, "dashboard:view")
    assert result["result"] == "DENY"
    assert "no role" in result["reason"]
