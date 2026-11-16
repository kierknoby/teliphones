"""0.8.0 security regressions. State models only; no host networking changes."""
import json
import threading
import time
import unittest
from unittest.mock import patch, Mock

import test_support_broker as helpers

broker = helpers.broker_module


class SecurityGenerationTests(unittest.TestCase):
    setUp = helpers.WorkstationPairingTests.setUp
    tearDown = helpers.WorkstationPairingTests.tearDown
    pair = helpers.WorkstationPairingTests.pair
    open_session = helpers.WorkstationPairingTests.open_session

    def test_close_failure_never_restores_open_or_lease(self):
        _, peer = self.pair()
        self.open_session(peer)
        with patch.object(self.broker, 'reconcile_listener', side_effect=broker.BrokerError('generation failed')):
            with self.assertRaises(broker.BrokerError):
                self.broker.dispatch({'action': 'workstation-policy', 'state': 'closed'}, 1000)
        self.assertEqual(self.broker.workstation_state()[0]['connection_state'], 'closed')
        self.assertEqual(self.broker.active_sessions(), {})
        self.assertFalse(self.net.up)
        restarted = broker.Broker()
        self.assertEqual(restarted.workstation_state()[0]['connection_state'], 'closed')

    def test_ssh_revoke_failure_is_durable(self):
        _, peer = self.pair(ssh='1')
        self.open_session(peer)
        with patch.object(self.broker, 'reconcile_listener', side_effect=broker.BrokerError('generation failed')):
            with self.assertRaises(broker.BrokerError):
                self.broker.dispatch({'action': 'workstation-ssh-revoke', 'workstation_id': peer['workstation_id']}, 1000)
        item = broker.Broker().workstation_state()[0]['workstations'][0]
        self.assertFalse(item['ssh'])
        self.assertNotIn('ssh_public_key', item)
        self.assertFalse(self.net.up)

    def test_revocation_preempts_foreground_wait_and_fences_completion(self):
        _, peer = self.pair()
        entered = threading.Event()
        errors = []
        original = self.broker.run
        def run(arguments, **kwargs):
            job = getattr(self.broker.request_context, 'listener_job', None)
            if job is not None and not entered.is_set():
                entered.set()
                if not job['cancel'].wait(2):
                    raise AssertionError('revocation did not preempt the foreground writer')
                # Simulate a success racing cancellation: generation fence must reject it.
                return ''
            return original(arguments, **kwargs)
        def writer():
            try:
                self.broker.dispatch({'action': 'web', 'web': 'http:8080'}, 1000)
            except Exception as error:
                errors.append(error)
        with patch.object(self.broker, 'run', side_effect=run):
            thread = threading.Thread(target=writer)
            thread.start()
            self.assertTrue(entered.wait(1))
            result = self.broker.dispatch({'action': 'unpair', 'workstation_id': peer['workstation_id']}, 1000)
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertTrue(result['ok'])
        self.assertIsInstance(errors[0], broker.Superseded)
        self.assertIn(peer['workstation_id'], self.broker.revocations()['records'])
        self.assertEqual(self.broker.workstation_state()[0]['workstations'], [])
        self.assertFalse(self.net.up)

    def test_stale_request_cannot_receive_new_lease(self):
        _, peer = self.pair()
        with self.assertRaisesRegex(broker.BrokerError, 'Stale'):
            self.broker.workstation_session('heartbeat', peer['address'].split('/')[0],
                                            received_at=time.monotonic() - 4)
        self.assertEqual(self.broker.active_sessions(), {})

    def test_actual_lock_wait_makes_queued_heartbeat_stale(self):
        _, peer = self.pair()
        errors = []
        def request():
            try:
                self.broker.workstation_session('heartbeat', peer['address'].split('/')[0],
                                                received_at=time.monotonic() - 4)
            except Exception as error:
                errors.append(error)
        with self.broker.wslock:
            thread = threading.Thread(target=request)
            thread.start()
        thread.join(1)
        self.assertIsInstance(errors[0], broker.BrokerError)
        self.assertEqual(self.broker.active_sessions(), {})

    def test_input_drop_and_interface_condition_never_report_active(self):
        self.pair()
        state, _ = self.broker.workstation_state()
        baseline = list(self.net.filter['INPUT'])
        for prefix, hook in (([['-j', 'DROP']], ['-j', 'fpbxfirewall']),
                             ([], ['-i', 'eth0', '-j', 'fpbxfirewall'])):
            self.net.filter['INPUT'] = prefix + baseline[:-1] + [hook]
            self.broker.firewall_integration(state)
            self.assertIn(self.broker.integration['state'], ('blocked', 'unknown'))

    def test_unknown_match_and_established_bypass_are_refused(self):
        self.pair()
        state, _ = self.broker.workstation_state()
        for rule in (['-m', 'unknown', '-j', 'ACCEPT'],
                     ['-m', 'conntrack', '--ctstate', 'ESTABLISHED', '-j', 'ACCEPT']):
            self.net.filter['INPUT'].insert(0, rule)
            self.broker.firewall_integration(state)
            self.assertEqual(self.broker.integration['state'], 'unknown')
            self.net.filter['INPUT'].pop(0)

    def test_independent_guard_has_deadline_and_terminal_tunnel_drop(self):
        _, peer = self.pair()
        self.open_session(peer)
        rules = [broker.iptables_rule(tokens) for tokens in self.net.filter[broker.INTEGRATION_CHAIN]]
        permits = [rule for rule in rules if rule.get('dport') in ('80', '443')]
        self.assertEqual(len(permits), 2)
        self.assertTrue(all('datestop' in rule for rule in permits))
        self.assertIn({'i': 'tlp-admin', 'comment': broker.INTEGRATION_MARK, 'j': 'DROP'}, rules)
        self.net.table = None
        # These are still installed even when the native nft gate is absent.
        self.assertEqual(rules, [broker.iptables_rule(tokens) for tokens in self.net.filter[broker.INTEGRATION_CHAIN]])

    def test_failed_integration_withdraws_existing_lease(self):
        _, peer = self.pair()
        self.open_session(peer)
        self.net.filter['INPUT'].insert(0, ['-j', 'REJECT'])
        with self.assertRaises(broker.BrokerError):
            self.broker.reconcile_integration(self.broker.workstation_state()[0])
        self.assertFalse(self.net.up)
        self.assertEqual(self.broker.active_sessions(), {})

    def test_nested_authority_lock_is_fully_released_for_wait(self):
        lock = broker.AuthorityLock()
        acquired = threading.Event()
        def acquire():
            with lock:
                acquired.set()
        with lock, lock:
            with lock.external_wait():
                thread = threading.Thread(target=acquire)
                thread.start()
                self.assertTrue(acquired.wait(1))
            thread.join()

    def test_restart_cannot_reuse_an_old_generation(self):
        with self.broker.wslock:
            generation = self.broker.advance_generation()
        self.assertNotEqual(broker.Broker().generation, generation)

    def test_shutdown_latch_refuses_mutations_and_admission(self):
        _, peer = self.pair()
        self.broker.stopping.set()
        with self.assertRaises(broker.BrokerError):
            self.broker.dispatch({'action': 'workstation-policy', 'state': 'open'}, 1000)
        with self.assertRaises(broker.BrokerError):
            self.broker.workstation_session('heartbeat', peer['address'].split('/')[0])

    def test_controller_workers_are_bounded(self):
        server = object.__new__(broker.SessionServer)
        server.slots = threading.BoundedSemaphore(1)
        server.slots.acquire()
        server.shutdown_request = Mock()
        server.process_request('connection', ('100.64.0.2', 1))
        server.shutdown_request.assert_called_once_with('connection')

    def test_controller_socket_is_bound_to_wireguard_interface(self):
        server = object.__new__(broker.SessionServer)
        server.socket = Mock()
        server.interface = 'tlp-admin'
        server.server_address = ('100.64.0.1', 8766)
        with patch.object(broker.socketserver.TCPServer, 'server_bind'):
            server.server_bind()
        server.socket.setsockopt.assert_called_once_with(broker.socket.SOL_SOCKET,
                                                        broker.socket.SO_BINDTODEVICE, b'tlp-admin\0')

    def test_wall_clock_rollback_clears_authority(self):
        _, peer = self.pair()
        self.open_session(peer)
        self.broker.clock_sample = (time.time() + 60, time.monotonic())
        with self.assertRaisesRegex(broker.BrokerError, 'clock'):
            self.broker.check_clock()
        self.assertEqual(self.broker.active_sessions(), {})
        self.assertFalse(self.net.up)

    def test_slow_http_body_is_disconnected_without_admission(self):
        state = {'connection_state': 'open', 'subnet': '127.0.0.0/24',
                 'workstations': [{'id': 'a' * 16, 'address': '127.0.0.2/32'}]}
        self.broker.workstation_state = lambda: (state, False)
        self.broker.integration['state'] = 'active'
        with broker.socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        with patch.object(broker, 'SESSION_CONTROL_PORT', port), \
                patch.object(broker, 'REQUEST_MAX_AGE', 0.2), \
                patch.object(broker.SessionServer, 'server_bind', broker.ThreadingHTTPServer.server_bind):
            self.broker.session_server_enabled = True
            self.broker.reconcile_session_servers(state)
            try:
                with broker.socket.create_connection(('127.0.0.1', port), timeout=2) as client:
                    client.sendall(b'POST /workstation/session HTTP/1.1\r\nHost: test\r\nContent-Length: 25\r\n\r\n{')
                    self.assertEqual(client.recv(4096), b'')
                self.assertEqual(self.broker.active_sessions(), {})
            finally:
                self.broker.stop_session_servers()

    def test_competing_native_hook_is_unknown(self):
        self.pair()
        original = self.broker.run
        def run(arguments, **kwargs):
            if arguments[-3:] == ['-j', 'list', 'ruleset']:
                return json.dumps({'nftables': [{'chain': {'family': 'inet', 'table': 'foreign',
                    'name': 'filter', 'hook': 'input', 'prio': -10}}]})
            return original(arguments, **kwargs)
        with patch.object(self.broker, 'run', side_effect=run):
            self.broker.firewall_integration(self.broker.workstation_state()[0])
        self.assertEqual(self.broker.integration['state'], 'unknown')

    def test_shutdown_contains_even_when_listener_cancellation_fails(self):
        self.pair()
        with patch.object(self.broker, 'cancel_listener_repair',
                          side_effect=broker.BrokerError('helper did not stop')), \
                patch.object(self.broker, 'contain_workstations', wraps=self.broker.contain_workstations) as contain:
            with self.assertRaisesRegex(broker.BrokerError, 'helper did not stop'):
                self.broker.shutdown_workstations()
        contain.assert_called_once()
        self.assertTrue(self.broker.stopping.is_set())
        self.assertEqual(self.broker.active_sessions(), {})
        self.assertFalse(self.net.up)

    def test_failed_nonfilter_inventory_is_unknown(self):
        self.pair()
        original = self.broker.run
        def run(arguments, **kwargs):
            if arguments[-3:] == ['-t', 'raw', '-S']:
                return None
            return original(arguments, **kwargs)
        with patch.object(self.broker, 'run', side_effect=run):
            self.broker.firewall_integration(self.broker.workstation_state()[0])
        self.assertEqual(self.broker.integration['state'], 'unknown')
