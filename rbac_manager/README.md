# Role-Based Access Control (RBAC) Manager

## 1. Project title
**RBAC Manager: designing and enforcing a role/permission model for a multi-tenant application.**

## 2. Project objective
Build a complete, runnable access-control system that

* models **tenants, users, roles and permissions** as Python objects,
* stores the **role hierarchy as a directed graph** and resolves inherited permissions with BFS/DFS,
* decides every request with a **greedy permission-resolution algorithm**,
* supports **explicit allow and explicit deny** (deny always wins),
* enforces **strict tenant isolation**,
* writes an **audit log** of every decision,
* exposes everything through a **Flask web UI and JSON API**, and is covered by **pytest** tests.

## 3. Problem statement
A SaaS product serves many customers (tenants) from one code base. Each customer has staff with
different responsibilities. The system must answer one question quickly and safely:

> *May user U, acting inside tenant T, perform action P?*

Hard-coding `if user.is_admin` checks does not scale, makes inheritance hard to reason about, and
risks one customer reading another customer's data. RBAC solves this by attaching permissions to
**roles**, assigning roles to users, and letting roles inherit from each other.

## 4. Technologies used
| Area | Technology |
|---|---|
| Language | Python 3 (standard library for all logic) |
| Web / API | Flask |
| Database | SQLite (`sqlite3` from the standard library) |
| Front end | HTML5, CSS3, vanilla JavaScript (no React, no Node.js) |
| Testing | pytest |

## 5. Project architecture
```
 Browser (HTML/CSS/JS)  --->  Flask routes + JSON API (app.py)
                                       |
                                       v
                              RBACManager (rbac/manager.py)   <- facade, permission pipeline
                  +--------------------+--------------------+
                  v                    v                    v
          RoleGraph (graph.py)  GreedyPermissionResolver   AuditLog (audit.py)
          BFS / DFS / cycles    (permissions.py)                 |
                  \                    |                    /
                   +--------- Database (database.py) -------+
                                       |
                                    SQLite  (database.db)
```
Object-oriented design: `Entity` is the base class of `Tenant`, `Role`, `User` and `Permission`
(**inheritance**); attributes are private with read-only properties (**encapsulation**);
`RBACManager` *has* a `Database`, an `AuditLog` and a `GreedyPermissionResolver`, and builds a
`RoleGraph` (**composition**).

## 6. Folder structure
```
rbac_manager/
├── app.py                 Flask application (pages + API), run with: python app.py
├── demo.py                Command-line demonstration of all scenarios
├── requirements.txt       Flask, pytest
├── pytest.ini             pytest configuration
├── README.md
├── database.db            SQLite database (created automatically if missing)
├── rbac/
│   ├── __init__.py
│   ├── models.py          Entity, Tenant, Role, User
│   ├── permissions.py     Permission class + greedy resolver
│   ├── graph.py           RoleGraph (directed graph, BFS, DFS, cycle detection)
│   ├── manager.py         RBACManager (CRUD, check_permission, enforce)
│   ├── audit.py           AuditEntry, AuditLog
│   ├── database.py        Database class + SQL schema
│   └── errors.py          Custom exceptions
├── tests/                 pytest suite (conftest.py holds shared fixtures)
├── templates/             Jinja2 pages (base, index, dashboard, tenants, users,
│                          roles, permissions, hierarchy, audit)
├── static/css/style.css   Dark-blue theme
├── static/js/script.js    Forms, API calls, hierarchy drawing
└── data/seed_data.py      Demo data (tenants, users, roles, permissions, deny rule)
```

## 7. RBAC explanation
* **Permission**: one allowed action written `resource:action`, e.g. `products:update`.
* **Role**: a named bundle of permissions, e.g. *Editor*.
* **User**: receives roles, never raw permissions (except explicit denies).
* A request is allowed when one of the user's roles (directly or by inheritance) carries the permission and no deny rule blocks it.

## 8. Multi-tenancy explanation
Every role belongs to exactly **one tenant**. A user has a *home tenant* and may be added to other
tenants. When checking `(user, tenant, permission)` the system

1. rejects the request if the user is **not a member** of the tenant (`TenantAccessDeniedError`, result `DENY`),
2. only considers roles whose `tenant_id` equals the requested tenant, so an ACME role never leaks into GLOBEX,
3. only applies deny rules stored for that tenant,
4. refuses role inheritance links between roles of different tenants.

## 9. Role hierarchy explanation
```
Admin      inherits Manager's permissions
  |
Manager    inherits Editor's permissions
  |
Editor     inherits Viewer's permissions
  |
Viewer     base role
```
Inheritance only flows **downwards**: Admin gets Viewer's permissions, Viewer never gets Admin's.

## 10. Graph algorithm
The hierarchy is a **directed graph** with an edge `parent -> child` meaning *child inherits parent*:

```
Viewer -> Editor -> Manager -> Admin
```

| Operation | Algorithm | Where |
|---|---|---|
| Collect all inherited roles of a user | **BFS** over parent links with a `visited` set | `RoleGraph.traverse_inherited` |
| Is there a path A -> B? | iterative **DFS** | `RoleGraph.has_path` |
| Reject circular inheritance | adding `parent -> child` is illegal if `parent` is already reachable from `child` | `RoleGraph.would_create_cycle` |
| Validate a whole graph | **Kahn's algorithm** (topological sort) | `RoleGraph.has_cycle` |

Example: `Viewer -> Editor -> Manager -> Admin` is accepted. Adding `Admin -> Viewer` is rejected with
`CircularRoleError`, because Admin is already reachable from Viewer. The `visited` set also protects
traversal against cycles and against diamond-shaped hierarchies (each role is processed once).
Complexity: O(V + E).

## 11. Greedy permission resolution algorithm
Implemented in `rbac/permissions.py` (`GreedyPermissionResolver.resolve`):

1. Start with the roles **directly assigned** to the user in the requested tenant.
2. Traverse inherited roles with BFS (nearest role first).
3. For each role, **add every permission that is not already resolved** (the first role that offers a
   permission claims it; duplicates are skipped).
4. Continue until all reachable roles are processed.
5. Apply **explicit deny** rules, which have higher priority than any allow.
6. Return the final decision: `ALLOW` if the permission is resolved and not denied, otherwise `DENY` (default deny).

It is *greedy* because each permission is claimed at the first opportunity and that choice is never
revisited or backtracked. Complexity: O(V + E + P).

Complete check pipeline in `RBACManager.check_permission`:
user exists -> tenant exists -> user belongs to tenant -> permission exists -> collect tenant roles ->
greedy resolution -> explicit deny -> allow -> default deny. Every outcome is audit-logged.

## 12. Explicit deny mechanism
Rows in `explicit_denials` (`user`, `tenant`, `permission`) override everything else.
Alice is an ACME Admin and the Admin role grants `billing:delete`, but Alice has an explicit deny:

```
Alice -> ACME -> billing:delete -> DENY      (reason: Explicit deny rule)
Alice -> ACME -> billing:edit   -> ALLOW
```
The deny is checked **before** the allow, applies to one user in one tenant, and can be removed again.

## 13. Database design
SQLite file `database.db` (created automatically; seeded on first start).

| Table | Purpose / key columns |
|---|---|
| `tenants` | `tenant_id`, `name` (unique) |
| `users` | `user_id`, `username` (unique), `email`, `tenant_id` (home tenant) |
| `user_tenants` | extra table: `user_id`, `tenant_id`, lets a user belong to several tenants |
| `roles` | `role_id`, `role_name`, `tenant_id`, unique `(role_name, tenant_id)` |
| `permissions` | `permission_id`, `name` (unique, `resource:action`), `description` |
| `user_roles` | `user_id`, `role_id` |
| `role_permissions` | `role_id`, `permission_id` |
| `role_hierarchy` | `parent_role_id`, `child_role_id` (edge parent -> child) |
| `explicit_denials` | `user_id`, `tenant_id`, `permission_id`, `reason` |
| `audit_logs` | `timestamp`, `username`, `tenant`, `permission`, `result`, `reason` |

## 14. API documentation
All bodies are JSON. Errors look like `{"error": "message"}` with a matching status code
(400 validation, 403 tenant access, 404 not found, 409 duplicate or circular).

| Method | URL | Body / query | Description |
|---|---|---|---|
| GET | `/api/users` | `?tenant_id=` | List users |
| POST | `/api/users` | `username, email, tenant_id` | Create user |
| GET | `/api/roles` | `?tenant_id=` | List roles |
| POST | `/api/roles` | `role_name, tenant_id, permissions[]` | Create role |
| GET | `/api/permissions` | | List permissions |
| POST | `/api/permissions` | `name, description` | Create permission |
| POST | `/api/check-permission` | `user_id, tenant_id, permission` | Returns `{"result": "ALLOW" or "DENY", "reason": ...}` (always HTTP 200) |
| GET / POST | `/api/tenants` | `name` | List / create tenants |
| POST | `/api/assign-role`, `/api/remove-role` | `user_id, role_id` | Assign / remove a role |
| POST | `/api/user-tenants` | `user_id, tenant_id` | Add a user to another tenant |
| POST | `/api/role-permissions` (+ `/remove`) | `role_id, permission` | Grant / revoke a permission on a role |
| GET | `/api/hierarchy` | `?tenant_id=` | Nodes and edges of a tenant's hierarchy |
| POST | `/api/hierarchy` (+ `/remove`) | `child_role_id, parent_role_id` | Add / remove inheritance (cycle gives 409) |
| GET / POST | `/api/denials` (+ `/remove`) | `user_id, tenant_id, permission` | Explicit deny rules |
| GET | `/api/effective-permissions` | `?user_id=&tenant_id=` | Resolved permissions with source roles |
| GET | `/api/audit` | `?limit=&result=` | Audit entries |
| GET | `/api/stats` | | Dashboard counters |

Example:
```
POST /api/check-permission
{"user_id": 1, "tenant_id": 1, "permission": "billing:delete"}

200 {"result": "DENY", "reason": "Explicit deny rule", "username": "Alice",
     "tenant": "ACME", "permission": "billing:delete"}
```
Web pages: `/`, `/dashboard`, `/tenants`, `/users`, `/roles`, `/permissions`, `/hierarchy`, `/audit`.

## 15. How to install
```powershell
cd rbac_manager
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
(If PowerShell blocks activation: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`.)

## 16. How to run
```powershell
python app.py
```
Open **http://127.0.0.1:5000**. The database and demo data are created automatically on first start.

## 17. How to run tests
```powershell
python -m pytest
```
The suite has 79 test functions (91 test cases with parametrisation) across roles, permissions,
hierarchy, denials, tenants, manager/audit and the Flask API. Each test uses a fresh in-memory database.

## 18. Demo instructions
```powershell
python demo.py            # fresh in-memory database, repeatable output
python demo.py --use-db   # writes to database.db so the audit entries appear on the /audit page
```

## 19. Example outputs
```
=== RBAC DEMO ===

--- 1. Alice (ACME Admin) can use admin permissions ---
Alice -> ACME -> users:create -> ALLOW
Alice -> ACME -> roles:delete -> ALLOW
Alice -> ACME -> products:delete -> ALLOW

--- 2. Bob (ACME Viewer) only has viewer permissions ---
Bob -> ACME -> dashboard:view -> ALLOW
Bob -> ACME -> products:read -> ALLOW
Bob -> ACME -> users:delete -> DENY

--- 3. Carol (ACME Editor) inherits Viewer permissions through Editor ---
Carol -> ACME -> products:create -> ALLOW
Carol -> ACME -> products:read -> ALLOW
Carol -> ACME -> products:update -> DENY

--- 5. Alice's explicit deny overrides an inherited allow ---
Alice -> ACME -> billing:edit -> ALLOW
Alice -> ACME -> billing:delete -> DENY

--- 6. Tenant isolation: ACME users cannot access GLOBEX ---
Bob -> GLOBEX -> products:read -> DENY
Alice -> GLOBEX -> users:create -> DENY
Dave -> GLOBEX -> users:create -> ALLOW
Dave -> ACME -> users:create -> DENY
Carol -> GLOBEX -> products:read -> ALLOW
Carol -> GLOBEX -> products:create -> DENY

--- 7. Circular role inheritance is rejected ---
Existing chain: Viewer -> Editor -> Manager -> Admin (valid)
Admin -> Viewer REJECTED: Circular role inheritance rejected: Admin -> Viewer would create a cycle ('Admin' already inherits from 'Viewer')
```
Audit entry format: `Alice | ACME | billing:delete | DENY | Explicit deny rule`

## 20. Future enhancements
* Password login and sessions, so the acting user comes from authentication instead of a form field.
* Role-level deny rules and time-limited grants.
* Wildcard permissions (`products:*`) and resource-level (per-object) permissions.
* Caching of resolved permissions with invalidation when roles change.
* Export of audit logs (CSV) and pagination / search.
* Migrating SQLite to PostgreSQL for production multi-user deployments.
