"""The listener must receive only the documented fwconsole compatibility environment."""
import subprocess
import threading
import unittest

import test_support_broker as helpers

broker = helpers.broker_module


class ListenerEnvironmentTests(unittest.TestCase):
    def test_allowlist_has_required_root_identity_without_inheritance(self):
        self.assertEqual(broker.ENV["USER"], "root")
        self.assertEqual(broker.ENV["LOGNAME"], "root")
        self.assertEqual(broker.ENV["SHELL"], "/bin/bash")
        self.assertNotIn("PYTHONPATH", broker.ENV)
        self.assertNotIn("SECRET_FIXTURE", broker.ENV)

    def test_background_listener_uses_the_same_allowlist(self):
        job = {"cancel": threading.Event(), "done": threading.Event()}
        result = helpers.broker_module.Broker().run_background_listener_command(
            ["/usr/bin/env"], 5, job)
        self.assertEqual(result.returncode, 0, result.stderr)
        environment = dict(line.split("=", 1) for line in result.stdout.splitlines())
        self.assertEqual(environment, broker.ENV)

    def test_synchronous_listener_uses_the_same_allowlist(self):
        captured = {}
        original = subprocess.run

        def run(arguments, **kwargs):
            captured.update(kwargs.get("env", {}))
            return subprocess.CompletedProcess(arguments, 0, "", "")

        subprocess.run = run
        try:
            instance = broker.Broker()
            instance.run([broker.FWCONSOLE, "teliphones", "listener", "--listen-port=51821"])
        finally:
            subprocess.run = original
        self.assertEqual(captured, broker.ENV)


if __name__ == "__main__":
    unittest.main()
