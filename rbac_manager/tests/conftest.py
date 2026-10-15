"""Shared pytest fixtures. Every test gets a brand-new in-memory SQLite database."""

from types import SimpleNamespace

import pytest

from data.seed_data import seed_demo_data
from rbac import Database, RBACManager


@pytest.fixture
def manager():
    """An empty RBACManager (tables created, no data)."""
    return RBACManager(Database(":memory:"))


@pytest.fixture
def demo(manager):
    """A manager filled with the demo data, plus handy id shortcuts."""
    refs = seed_demo_data(manager)
    return SimpleNamespace(
        m=manager,
        acme=refs["tenants"]["ACME"],
        globex=refs["tenants"]["GLOBEX"],
        alice=refs["users"]["Alice"],
        bob=refs["users"]["Bob"],
        carol=refs["users"]["Carol"],
        dave=refs["users"]["Dave"],
        acme_roles=refs["roles"]["ACME"],
        globex_roles=refs["roles"]["GLOBEX"],
    )
