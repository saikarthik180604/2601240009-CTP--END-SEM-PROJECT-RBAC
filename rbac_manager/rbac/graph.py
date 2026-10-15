"""
RoleGraph - the role hierarchy stored as a DIRECTED GRAPH.

Vertices : role ids.
Edges    : parent -> child, meaning "child INHERITS the permissions of parent".

    Viewer -> Editor -> Manager -> Admin

Viewer is the base role. Admin (the most senior role) inherits everything
that Manager, Editor and Viewer have.

Algorithms used
---------------
* DFS (iterative)  - has_path(): is there a route from A to B?
                     Used for CYCLE DETECTION before adding an edge.
* BFS              - traverse_inherited() / ancestors(): visit all roles whose
                     permissions a role inherits. A `visited` set makes the
                     traversal safe even if a cycle ever existed.
* Kahn's algorithm - has_cycle(): validates a whole graph.
"""

from collections import deque

from .errors import CircularRoleError


class RoleGraph:
    def __init__(self):
        self._parents = {}   # role_id -> list of roles it inherits FROM
        self._children = {}  # role_id -> list of roles that inherit from it

    # ---------------------------------------------------------------- vertices
    def add_role(self, role_id):
        self._parents.setdefault(role_id, [])
        self._children.setdefault(role_id, [])

    def has_role(self, role_id):
        return role_id in self._parents

    @property
    def roles(self):
        return list(self._parents.keys())

    # ------------------------------------------------------------------- edges
    def add_edge(self, parent_id, child_id):
        """
        Make `child_id` inherit from `parent_id`  (edge parent -> child).
        Raises CircularRoleError if this would create a cycle.
        """
        self.add_role(parent_id)
        self.add_role(child_id)
        if parent_id in self._parents[child_id]:
            return  # edge already exists
        if self.would_create_cycle(parent_id, child_id):
            raise CircularRoleError(
                f"Circular role inheritance rejected: edge {parent_id} -> {child_id} would create a cycle"
            )
        self._parents[child_id].append(parent_id)
        self._children[parent_id].append(child_id)

    def remove_edge(self, parent_id, child_id):
        if parent_id in self._parents.get(child_id, []):
            self._parents[child_id].remove(parent_id)
            self._children[parent_id].remove(child_id)

    def has_edge(self, parent_id, child_id):
        return parent_id in self._parents.get(child_id, [])

    def edges(self):
        return [(p, c) for c, parents in self._parents.items() for p in parents]

    def parents_of(self, role_id):
        return list(self._parents.get(role_id, []))

    def children_of(self, role_id):
        return list(self._children.get(role_id, []))

    # ------------------------------------------------------------ cycle checks
    def has_path(self, start_id, goal_id):
        """
        Iterative DFS following parent -> child edges.
        Returns True if goal_id can be reached from start_id.
        (A role always reaches itself.)
        """
        stack = [start_id]
        visited = set()
        while stack:
            node = stack.pop()
            if node == goal_id:
                return True
            if node in visited:
                continue
            visited.add(node)
            stack.extend(self._children.get(node, []))
        return False

    def would_create_cycle(self, parent_id, child_id):
        """
        Adding parent -> child creates a cycle exactly when `parent` is
        ALREADY reachable from `child` (child -> ... -> parent exists).
        Example: chain Viewer->Editor->Manager->Admin, adding Admin->Viewer:
        Admin is reachable from Viewer, so the new edge closes a loop.
        """
        return self.has_path(child_id, parent_id)

    def has_cycle(self):
        """Kahn's algorithm: the graph is acyclic iff every vertex can be removed."""
        in_degree = {r: len(p) for r, p in self._parents.items()}
        queue = deque(r for r, d in in_degree.items() if d == 0)
        removed = 0
        while queue:
            node = queue.popleft()
            removed += 1
            for child in self._children.get(node, []):
                in_degree[child] -= 1
                if in_degree[child] == 0:
                    queue.append(child)
        return removed != len(in_degree)

    # -------------------------------------------------------------- traversals
    def traverse_inherited(self, start_ids):
        """
        BFS upwards through the hierarchy.

        Starting from the user's assigned roles, visit every role whose
        permissions are inherited. Returns role ids in visiting order
        (assigned roles first, then the nearest inherited roles, and so on).
        The `visited` set guarantees each role is processed once - this is the
        protection against cycles and against diamond-shaped hierarchies.
        """
        order = []
        visited = set()
        queue = deque()
        for role_id in start_ids:
            if role_id not in visited:
                visited.add(role_id)
                queue.append(role_id)
        while queue:
            role_id = queue.popleft()
            order.append(role_id)
            for parent in self._parents.get(role_id, []):
                if parent not in visited:
                    visited.add(parent)
                    queue.append(parent)
        return order

    def ancestors(self, role_id):
        """All roles that `role_id` inherits from (itself excluded), BFS order."""
        return self.traverse_inherited([role_id])[1:]

    def descendants(self, role_id):
        """All roles that inherit (directly or not) from `role_id`, BFS order."""
        order, visited, queue = [], {role_id}, deque([role_id])
        while queue:
            node = queue.popleft()
            for child in self._children.get(node, []):
                if child not in visited:
                    visited.add(child)
                    order.append(child)
                    queue.append(child)
        return order
