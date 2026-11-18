"""Serialized listener transactions using isolated network/state fixtures."""
import threading
import unittest
from unittest.mock import patch

import test_listener_scheduling as scheduling
import test_support_broker as helpers

broker = helpers.broker_module


class ListenerConcurrencyTests(unittest.TestCase):
    setUp = helpers.WorkstationPairingTests.setUp
    tearDown = helpers.WorkstationPairingTests.tearDown
    open_paired = scheduling.ListenerSchedulingTests.open_paired

    def test_background_does_not_replace_shared_listener_method(self):
        original = self.broker.reconcile_listener
        observed = []

        def inspect():
            # A concurrent observer need not acquire wslock to read an instance method.
            worker = threading.Thread(target=lambda: observed.append(self.broker.reconcile_listener))
            worker.start()
            worker.join(5)
            self.assertFalse(worker.is_alive())

        with patch.object(self.broker, 'expire_workstations_locked', side_effect=inspect):
            self.broker.expire_workstations()
        self.assertEqual(observed, [original])
        self.assertEqual(self.broker.reconcile_listener, original)

    def test_background_listener_failure_is_contained_and_retried(self):
        self.open_paired()
        self.net.filter[self.generated['51821']] = []
        self.fail_listener = True
        self.broker.expire_workstations()
        self.assertFalse(self.net.up)
        self.assertTrue(self.broker.workstation_reconcile_failing)
        self.assertGreater(self.broker.workstation_retry_at, 0)
        self.assertIn('listener fixture failed', self.broker.workstation_error)
        self.fail_listener = False
        self.broker.workstation_retry_at = 0
        self.broker.expire_workstations()
        self.assertTrue(self.net.up)
        self.assertFalse(self.broker.workstation_reconcile_failing)
        self.assertEqual(self.net.peers, self.expected_peers)

    def test_slow_background_repair_allows_heartbeat_expiry_and_is_cancelled_by_close(self):
        self.open_paired()
        self.net.filter[self.generated['51821']] = []
        entered = threading.Event()
        original = self.broker.run
        jobs = []

        def run(arguments, **kwargs):
            job = getattr(self.broker.request_context, 'listener_job', None)
            if job is not None and not job.get("foreground"):
                jobs.append(job)
                entered.set()
                if not job['cancel'].wait(3):
                    raise AssertionError('Newer policy did not cancel stale repair')
                raise broker.BrokerError('Cancelled fixture')
            return original(arguments, **kwargs)

        self.broker.run = run
        try:
            self.broker.expire_workstations()
            self.assertTrue(entered.wait(1))
            peer = self.expected_workstations[0]
            response = self.broker.workstation_session('heartbeat', peer['address'].split('/')[0])
            self.assertTrue(response['active'])
            expires = self.broker.active_sessions()[peer['id']]['expires_at']
            with patch.object(broker.time, 'time', return_value=expires + 1):
                self.broker.expire_sessions()
                self.assertEqual(self.broker.active_sessions(include_expired=True), {})
            self.broker.dispatch({'action': 'workstation-policy', 'state': 'closed'}, 1000)
            self.assertTrue(jobs[0]['done'].is_set())
            self.assertIsNone(self.broker.listener_job)
            self.assertFalse(self.net.up)
            self.assertEqual(self.generated, {})
            self.broker.expire_workstations()
            self.assertEqual(self.generated, {})
        finally:
            self.broker.cancel_listener_repair()

    def test_revocation_supersedes_slow_listener_repair(self):
        self.open_paired()
        self.net.filter[self.generated['51821']] = []
        original = self.broker.run
        jobs = []

        def run(arguments, **kwargs):
            job = getattr(self.broker.request_context, 'listener_job', None)
            if job is not None and not job.get("foreground"):
                jobs.append(job)
                if not job['cancel'].wait(3):
                    raise AssertionError('Revocation did not cancel repair')
                raise broker.BrokerError('Cancelled fixture')
            return original(arguments, **kwargs)

        self.broker.run = run
        try:
            self.broker.expire_workstations()
            result = self.broker.dispatch({'action': 'unpair', 'workstation_id': 'all'}, 1000)
            self.assertTrue(result['ok'])
            self.assertTrue(jobs[0]['done'].is_set())
            self.assertFalse(self.net.up)
            self.assertEqual(self.generated, {})
            self.assertEqual(self.broker.workstation_state()[0]['workstations'], [])
            self.broker.expire_workstations()
            self.assertEqual(self.generated, {})
        finally:
            self.broker.cancel_listener_repair()

    def test_all_management_accepts_have_exact_kernel_deadlines(self):
        self.open_paired()
        peer = self.expected_workstations[0]
        state, _ = self.broker.workstation_state()
        cutoff = int(broker.time.time()) + 10
        state['workstations'][0].update(mode='temporary', expires_at=cutoff)
        self.broker.save_active_sessions({peer['id']: {'expires_at': cutoff + 300}})
        policy = self.broker.expected_policy(state)
        timestamp = broker.datetime.datetime.fromtimestamp(cutoff, broker.datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        guards = []
        for entry in policy['nftables']:
            expr = entry.get('rule', {}).get('expr', [])
            ports = [x['match']['right'] for x in expr if x.get('match', {}).get('left') ==
                     {'payload': {'protocol': 'tcp', 'field': 'dport'}}]
            if ports and ports != [broker.SESSION_CONTROL_PORT] and {'accept': None} in expr:
                guard = {'match': {'op': '<', 'left': {'meta': {'key': 'time'}}, 'right': timestamp}}
                self.assertIn(guard, expr)
                guards.append(guard)
        self.assertTrue(guards)
        with self.assertRaisesRegex(broker.BrokerError, 'absolute expiry'):
            broker.workstation_policy('100.70.1.1', [], admitted_sources=['100.70.1.2'])

    def test_cancellation_reaps_real_helper_and_stops_its_child(self):
        import sys
        import time
        from pathlib import Path
        helper = Path(self.directory.name) / 'listener_fixture.py'
        child_pid = Path(self.directory.name) / 'child.pid'
        helper.write_text('''import subprocess,sys,time
subprocess.Popen([sys.executable, '-c',
    'import os,pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)', sys.argv[1]])
time.sleep(30)
''')
        job = {'cancel': threading.Event(), 'done': threading.Event()}
        errors = []

        def run():
            try:
                self.broker.run_background_listener_command([sys.executable, str(helper), str(child_pid)], 30, job)
            except Exception as error:
                errors.append(error)
            finally:
                job['done'].set()

        worker = threading.Thread(target=run)
        worker.start()
        try:
            deadline = time.monotonic() + 3
            while not child_pid.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(child_pid.exists(), 'Fixture child did not start')
            self.broker.listener_job = job
            self.broker.cancel_listener_repair()
            self.assertTrue(job['done'].is_set())
            self.assertIsNone(self.broker.listener_job)
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], broker.BrokerError)
            status = Path('/proc') / child_pid.read_text() / 'stat'
            def reaped_or_zombie():
                try:
                    return not status.exists() or status.read_text().split()[2] == 'Z'
                except (FileNotFoundError, ProcessLookupError):
                    # The process exited between the existence and read checks;
                    # that is the successful reaped state being asserted.
                    return True
            deadline = time.monotonic() + 1
            while not reaped_or_zombie() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(reaped_or_zombie(), 'Cancelled descendant remains runnable')
        finally:
            job['cancel'].set()
            worker.join(3)
        self.assertFalse(worker.is_alive())
