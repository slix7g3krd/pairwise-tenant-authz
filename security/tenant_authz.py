"""Tenant authorization helpers for multi-tenant SaaS.

All checks fail closed: missing tenant, soft-deleted objects, and
cross-tenant access are denied. Only ``system_admin`` may cross tenants,
and its role is only honored when asserted inside its own tenant context.
"""

SYSTEM_ROLES = frozenset({'system_admin'})


def _tenant_of(obj):
    if not isinstance(obj, dict):
        return None
    tenant = obj.get('tenant')
    return tenant or None


def can_access(obj, user_tenant, resource_tenant, visible=True):
    """Object-level tenant check.

    ``visible`` is accepted for API compatibility (uniform-error callers
    pass visible=False to avoid leaking object existence); it never
    grants access by itself.
    """
    tenant = _tenant_of(obj)
    if tenant is None:
        return False
    if obj.get('deleted'):
        # Soft-deleted objects are not accessible by id.
        return False
    if obj.get('role') in SYSTEM_ROLES and tenant == user_tenant:
        # system_admin may cross tenants, but the role is only trusted
        # when asserted within the tenant it belongs to.
        return True
    # Role (e.g. admin) is scoped to its tenant: require the object,
    # the user, and the resource to all live in the same tenant.
    return tenant == resource_tenant and user_tenant == resource_tenant


def filter_for_tenant(items, tenant):
    """Uniform tenant filter for list/pagination/export/batch paths."""
    return [
        item for item in items
        if _tenant_of(item) == tenant and not item.get('deleted')
    ]


def cache_key(tenant, key):
    """Cache keys always embed the tenant to prevent cross-tenant reads."""
    return '{}:{}'.format(tenant, key)


def batch_authorize(obj, tenant, resource_tenants):
    """Batch check: every requested id must resolve to the caller's tenant."""
    if _tenant_of(obj) != tenant or obj.get('deleted'):
        return False
    if not resource_tenants:
        return False
    return all(t == tenant for t in resource_tenants)


def invite_ok(invite, tenant):
    """Invites are bound to the tenant/workspace that issued them."""
    return _tenant_of(invite) == tenant
