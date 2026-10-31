from pathlib import Path
import json
import threading
import sys

import test_manager as fixtures
from lsm.discovery import inspect_directory
from lsm.manager import Manager
from lsm.server import AppServer
from lsm import processes as proc


class BlacklistTests(fixtures.Fixture):
    def sample(self, name, version='1.0.0'):
        directory = self.root / 'samples' / name
        directory.mkdir(parents=True)
        (directory / 'package.json').write_text(json.dumps({
            'name': 'same-name-tool', 'version': version,
            'scripts': {'start': 'node server.js --port 18723'},
        }), encoding='utf-8')
        return directory, inspect_directory(directory, {'package.json'})

    def test_exact_installation_persist_repeat_scan_and_restore(self):
        manager = self.make_manager()
        one, first = self.sample('one')
        two, second = self.sample('two', '2.0.0')
        manager.merge(first)
        manager.merge(second)
        self.assertEqual(1, manager.add_blacklist({'service_ids': [first['id']]}))
        self.assertNotIn(first['id'], manager.configs)
        self.assertIn(second['id'], manager.configs)
        # A version change in the same installation cannot bypass the path rule.
        (one / 'package.json').write_text(json.dumps({'name': 'same-name-tool', 'version': '1.1.0',
                                                     'scripts': {'start': 'node server.js'}}), encoding='utf-8')
        self.assertFalse(manager.merge(inspect_directory(one, {'package.json'})))
        manager.close()
        self.manager = manager = Manager(manager.root, seed=False, monitor=False)
        self.assertTrue(manager.is_blacklisted(one))
        self.assertFalse(manager.is_blacklisted(two))
        self.assertFalse(manager.is_blacklisted(one / 'different-installation'))
        manager.scanner.start([str(one.parent)])
        fixtures.wait_for(lambda: not manager.scanner.snapshot()['running'])
        self.assertEqual(1, manager.scanner.snapshot()['blacklisted'])
        self.assertEqual(1, manager.scanner.snapshot()['found'])
        self.assertEqual({second['id']}, set(manager.configs))
        manager.remove_blacklist(manager.list_blacklist()[0]['id'])
        self.assertNotIn(first['id'], manager.configs)  # Restore doesn't execute/register anything.
        manager.scanner.start([str(one.parent)])
        fixtures.wait_for(lambda: not manager.scanner.snapshot()['running'])
        self.assertEqual(2, len(manager.configs))
        self.assertEqual('1.1.0', manager.configs[first['id']]['version'])

    def test_batch_is_atomic_and_protects_running_services(self):
        manager = self.make_manager()
        _, first = self.sample('one')
        _, second = self.sample('two')
        manager.merge(first)
        manager.merge(second)
        manager.states[second['id']] = {'status': 'running', 'owned': True}
        with self.assertRaisesRegex(ValueError, '运行中'):
            manager.add_blacklist({'entries': [first, second]})
        self.assertEqual([], manager.list_blacklist())
        self.assertEqual(2, len(manager.configs))
        manager.states[second['id']] = {'status': 'stopped'}
        self.assertEqual(2, manager.add_blacklist({'entries': [first, second]}))
        self.assertEqual({}, manager.configs)
        self.assertEqual(2, len(manager.list_blacklist()))
        # Duplicate imports don't create duplicate exclusions.
        manager.add_blacklist({'entries': [first]})
        self.assertEqual(2, len(manager.list_blacklist()))

    def test_corrupt_blacklist_is_not_silently_erased(self):
        manager = self.make_manager()
        manager.close()
        manager.blacklist_file.write_text('{broken', encoding='utf-8')
        with self.assertRaises(ValueError):
            Manager(manager.root, seed=False, monitor=False)
        self.assertEqual('{broken', manager.blacklist_file.read_text(encoding='utf-8'))
        self.manager = None


class ProcessHandshakeTests(fixtures.Fixture):
    def test_process_mode_detects_business_exit_with_supervisor_still_present(self):
        manager = self.make_manager()
        command = [sys.executable, '-c', 'import time;time.sleep(30)']
        config = self.http_config(command=command, health_mode='process', url='')
        sid = manager.save_config(config)
        manager.action(sid, 'start')
        fixtures.wait_for(lambda: not manager.operations)
        self.assertEqual('running', manager.states[sid]['status'])
        business = next(record for record in manager.instances[sid]['members']
                        if record['command_hash'] == proc.command_hash(command))
        self.assertTrue(proc.force_stop([business]))
        fixtures.wait_for(lambda: not proc.verified(business))
        for _ in range(3):
            manager.refresh()
        self.assertEqual('error', manager.states[sid]['status'])


class BlacklistApiTests(fixtures.Fixture):
    request = fixtures.ApiTests.request

    def setUp(self):
        super().setUp()
        self.server = AppServer(self.root / 'api', 0, seed=False)
        self.manager = self.server.manager
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.origin, self.token = self.server.origin, self.server.token

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def test_blacklist_api_source_guard_add_list_remove(self):
        self.assertEqual(403, self.request('/api/blacklist', token=False)[0])
        entry = {'name': 'API test', 'directory': str(self.root / 'tool'), 'version': '1.0'}
        self.assertEqual(403, self.request('/api/blacklist', 'POST', {'entries': [entry]}, origin='https://evil.test')[0])
        code, body = self.request('/api/blacklist', 'POST', {'entries': [entry]})
        self.assertEqual(200, code, body)
        row = json.loads(body)['entries'][0]
        self.assertEqual(1, json.loads(self.request('/api/services')[1])['blacklist_count'])
        self.assertEqual(200, self.request('/api/blacklist/' + row['id'], 'DELETE', {})[0])
        self.assertEqual([], json.loads(self.request('/api/blacklist')[1])['entries'])
