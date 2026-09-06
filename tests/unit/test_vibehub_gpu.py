from types import SimpleNamespace
import json

import pytest

from backend.oj_modules.vibehub import gpu

UUID = 'GPU-12345678-1234-1234-1234-123456789abc'
NAME = 'numoj-vh-' + '1' * 16 + '-' + '2' * 40


@pytest.mark.parametrize('value', [True, -1, 1, 255, 24577, '1.5', None, {}, 'all'])
def test_gpu_rejects_invalid_limits(value):
    with pytest.raises(gpu.GPUError):
        gpu.memory_limit(value)


def test_new_version_never_inherits_approval_or_trusts_uploaded_permission():
    manifest = {'gpu_memory_mib': 24000, 'gpu_approved_memory_mib': 24000}
    previous = json.dumps({'gpu_memory_mib': 4096, 'gpu_approved_memory_mib': 2048})
    gpu.set_request(manifest, {}, previous=previous)
    assert manifest == {'gpu_memory_mib': 4096}
    gpu.set_request(manifest, {'gpu_memory_mib': '0'}, previous=previous)
    assert manifest == {}
    gpu.set_request(manifest, {})
    assert manifest == {}


def test_gpu_monitor_sums_host_pids_and_ignores_other_containers_and_devices():
    def run(args, **kwargs):
        if args[:2] == ['docker', 'top']:
            return SimpleNamespace(returncode=0, stdout='PID\n21\n22\n')
        return SimpleNamespace(returncode=0, stdout=f'{UUID},21,800\n{UUID},22,900\n{UUID},23,2000\nGPU-00000000-0000-0000-0000-000000000000,21,5000')
    cli = SimpleNamespace(_run=run, container_running=lambda _: True)
    runtimes = {'a': {'container_name': NAME, 'gpu': {'device': UUID}}}
    assert gpu.usage(cli, runtimes) == {'a': 1700}


def test_unavailable_gpu_measurement_is_an_error_not_zero_usage():
    cli = SimpleNamespace(
        _run=lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=f'{UUID},21,[N/A]'),
        container_running=lambda _: False,
    )
    with pytest.raises(gpu.GPUError, match='显存监测'):
        gpu.usage(cli, {'a': {'container_name': NAME, 'gpu': {'device': UUID}}})


def test_gpu_budget_is_per_project_across_containers():
    runtimes = {
        'public': {'project_key': 'a', 'gpu': {'memory_mib': 4096}},
        'preview': {'project_key': 'a', 'gpu': {'memory_mib': 4096}},
        'other': {'project_key': 'b', 'gpu': {'memory_mib': 4096}},
    }
    assert gpu.over_limit_projects(runtimes, {'public': 2500, 'preview': 2000, 'other': 4000}) == {'a'}
    assert gpu.over_limit_projects(runtimes, {'public': 2000, 'preview': 2000, 'other': 4000}) == set()
    runtimes['preview']['gpu']['memory_mib'] = 8192
    assert gpu.over_limit_projects(runtimes, {'public': 4500, 'preview': 1000, 'other': 4000}) == {'a'}


def test_policy_reaper_invalidates_replaced_rejected_and_reduced_allocations(monkeypatch):
    rows = [{
        'id': 12, 'slug': 'demo', 'latest_version_id': 12, 'review_version_id': 12,
        'public_version_id': 10, 'review_status': 'pending',
        'manifest_json': '{"gpu_memory_mib":4096}',
    }]
    class Cursor:
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def execute(self, *_): pass
        def fetchall(self): return rows
    conn = SimpleNamespace(cursor=Cursor, close=lambda: None)
    monkeypatch.setattr(gpu, 'get_db_connection', lambda: conn)
    runtimes = {'a': {'project_key': 'demo', 'channel': 'review', 'gpu': {'version_id': 12, 'memory_mib': 4096}}}
    assert gpu.invalid_allocations(runtimes) == set()
    rows[0]['review_status'] = 'rejected'
    assert gpu.invalid_allocations(runtimes) == {'a'}
    rows[0].update(review_status='approved', public_version_id=12, review_version_id=None, manifest_json='{"gpu_memory_mib":4096,"gpu_approved_memory_mib":2048}')
    runtimes['a']['channel'] = 'public'
    assert gpu.invalid_allocations(runtimes) == {'a'}
    runtimes['a']['gpu']['memory_mib'] = 2048
    assert gpu.invalid_allocations(runtimes) == set()
    rows[0]['public_version_id'] = 13
    assert gpu.invalid_allocations(runtimes) == {'a'}


def test_device_checks_uuid_and_allows_driver_reserved_memory_rounding():
    cli = SimpleNamespace(_run=lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=f'{UUID},24564'))
    assert gpu.device(cli, 24576) == UUID
