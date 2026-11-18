import pytest

from security.tenant_authz import (
    can_access,
    filter_for_tenant,
    cache_key,
    batch_authorize,
    invite_ok
)


def test_same():
    assert can_access({'tenant': 't1'}, 't1', 't1') is True

def test_cross():
    assert can_access({'tenant': 't1'}, 't1', 't2') is False

def test_admin_cross():
    assert can_access({'tenant': 't1', 'role': 'admin'}, 't1', 't2') is False

def test_filter():
    assert filter_for_tenant([{'tenant': 't1'}, {'tenant': 't2'}], 't1') == [{'tenant': 't1'}]

def test_cache():
    assert cache_key('t1', 'k') != cache_key('t2', 'k')

def test_batch():
    assert batch_authorize({'tenant': 't1'}, 't1', {'t1', 't1'}) is True

def test_batch_bad():
    assert batch_authorize({'tenant': 't1'}, 't1', {'t1', 't2'}) is False

def test_invite():
    assert invite_ok({'tenant': 't1'}, 't1') is True

def test_invite_bad():
    assert invite_ok({'tenant': 't1'}, 't2') is False

def test_soft_delete():
    assert can_access({'tenant': 't1', 'deleted': True}, 't1', 't1') is False

def test_role_tenant():
    assert can_access({'tenant': 't1', 'role': 'admin'}, 't2', 't2') is False

def test_empty():
    assert can_access({}, 't1', 't1') is False

def test_pagination():
    assert filter_for_tenant([{'tenant': 't1', 'id': 1}], 't1') == [{'tenant': 't1', 'id': 1}]

def test_system_admin():
    assert can_access({'tenant': 't1', 'role': 'system_admin'}, 't1', 't2') is True

def test_error():
    assert can_access({'tenant': 't1'}, 't1', 't1', visible=False) is True
