# Copyright (C) 2014 eNovance SAS <licensing@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#

import os
import signal
import textwrap
from unittest import mock

from neutron_lib import constants as n_consts
from oslo_config import cfg
from oslo_utils import uuidutils
import testtools

from neutron.agent.linux import external_process
from neutron.agent.linux import keepalived
from neutron.conf.agent.l3 import config as l3_config
from neutron.tests import base

# Keepalived user guide:
# http://www.keepalived.org/pdf/UserGuide.pdf

KEEPALIVED_GLOBAL_CONFIG = textwrap.dedent("""\
    global_defs {
        notification_email_from %(email_from)s
        router_id %(router_id)s
    }
    """) % dict(email_from=keepalived.KEEPALIVED_EMAIL_FROM,
                router_id=keepalived.KEEPALIVED_ROUTER_ID)
KEEPALIVED_VR_1_CONFIG = textwrap.dedent("""\
    vrrp_instance VR_1 {
        state MASTER
        interface eth0
        virtual_router_id 1
        priority 50
        garp_master_delay 60""")
KEEPALIVED_VR_1_TRACK_IF = """
    advert_int 5
    authentication {
        auth_type AH
        auth_pass pass123
    }
    track_interface {
        eth0
    }"""
KEEPALIVED_VR_1_VIP = """
    virtual_ipaddress {
        169.254.0.1/24 dev eth0
    }"""
KEEPALIVED_VR_1_VIPEX_x4 = """
    virtual_ipaddress_excluded {{
        192.168.1.0/24 dev eth1{notrk}
        192.168.2.0/24 dev eth2{notrk}
        192.168.3.0/24 dev eth2{notrk}
        192.168.55.0/24 dev eth10{notrk}
    }}"""
KEEPALIVED_VR_1_VIPEX_x1 = """
    virtual_ipaddress_excluded {{
        192.168.1.0/24 dev eth1{notrk}
    }}"""
KEEPALIVED_VR_1_VRTS_A = """
    virtual_routes {{
        0.0.0.0/0 via 192.168.1.1 dev eth1{notrk}
    }}"""
KEEPALIVED_VR_1_VRTS_B = """
    virtual_routes {{
        12.0.0.0/24 via 10.0.0.1{notrk}
    }}"""
KEEPALIVED_VR_1_TRACK_SCRIPT = """
    track_script {
        ha_health_check_1
    }"""
KEEPALIVED_VR_1_CLOSE = """
    }"""
KEEPALIVED_VR_2_CONFIG = textwrap.dedent("""
    vrrp_instance VR_2 {
        state MASTER
        interface eth4
        virtual_router_id 2
        priority 50
        garp_master_delay 60
        mcast_src_ip 224.0.0.1""")
KEEPALIVED_VR_2_TRACK_IF = """
    track_interface {
        eth4
    }"""
KEEPALIVED_VR_2_VIP = """
    virtual_ipaddress {
        169.254.0.2/24 dev eth4
    }"""
KEEPALIVED_VR_2_VIPEX = """
    virtual_ipaddress_excluded {{
        192.168.2.0/24 dev eth2{notrk}
        192.168.3.0/24 dev eth6{notrk}
        192.168.55.0/24 dev eth10{notrk}
    }}"""
KEEPALIVED_VR_2_CLOSE = """
    }
"""
KEEPALIVED_TRACK_SCRIPT = """\
vrrp_script ha_health_check_1 {
    script "/etc/ha_confs/qrouter-x/ha_check_script_1.sh"
    interval 5
    fall 2
    rise 2
}
"""

NOTRACK = ' no_track'

VRRP_ID = 1
VRRP_INTERVAL = 5


class KeepalivedBaseTestCase(base.BaseTestCase):

    def setUp(self):
        super(KeepalivedBaseTestCase, self).setUp()
        l3_config.register_l3_agent_config_opts(l3_config.OPTS, cfg.CONF)
        cfg.CONF.set_override('keepalived_templates_path', 'etc/neutron')


class KeepalivedGetFreeRangeTestCase(KeepalivedBaseTestCase):
    def test_get_free_range(self):
        free_range = keepalived.get_free_range(
            parent_range='169.254.0.0/16',
            excluded_ranges=['169.254.0.0/24',
                             '169.254.1.0/24',
                             '169.254.2.0/24'],
            size=24)
        self.assertEqual('169.254.3.0/24', free_range)

    def test_get_free_range_without_excluded(self):
        free_range = keepalived.get_free_range(
            parent_range='169.254.0.0/16',
            excluded_ranges=[],
            size=20)
        self.assertEqual('169.254.0.0/20', free_range)

    def test_get_free_range_excluded_out_of_parent(self):
        free_range = keepalived.get_free_range(
            parent_range='169.254.0.0/16',
            excluded_ranges=['255.255.255.0/24'],
            size=24)
        self.assertEqual('169.254.0.0/24', free_range)

    def test_get_free_range_not_found(self):
        tiny_parent_range = '192.168.1.0/24'
        huge_size = 8
        with testtools.ExpectedException(ValueError):
            keepalived.get_free_range(
                parent_range=tiny_parent_range,
                excluded_ranges=[],
                size=huge_size)


class KeepalivedConfBaseMixin(object):

    def _get_config(self, with_vips=True):
        config = keepalived.KeepalivedConf()

        instance1 = keepalived.KeepalivedInstance('MASTER', 'eth0', 1,
                                                  ['169.254.192.0/18'],
                                                  advert_int=5)
        instance1.set_authentication('AH', 'pass123')
        instance1.track_interfaces.append("eth0")

        if with_vips:
            vip_address1 = keepalived.KeepalivedVipAddress('192.168.1.0/24',
                                                           'eth1', track=False)

            vip_address2 = keepalived.KeepalivedVipAddress('192.168.2.0/24',
                                                           'eth2', track=False)

            vip_address3 = keepalived.KeepalivedVipAddress('192.168.3.0/24',
                                                           'eth2', track=False)

            vip_address_ex = keepalived.KeepalivedVipAddress('192.168.55.0/24',
                                                             'eth10',
                                                             track=False)

            instance1.vips.append(vip_address1)
            instance1.vips.append(vip_address2)
            instance1.vips.append(vip_address3)
            instance1.vips.append(vip_address_ex)

        virtual_route = keepalived.KeepalivedVirtualRoute(n_consts.IPv4_ANY,
                                                          "192.168.1.1",
                                                          "eth1")
        instance1.virtual_routes.gateway_routes = [virtual_route]

        instance2 = keepalived.KeepalivedInstance('MASTER', 'eth4', 2,
                                                  ['169.254.192.0/18'],
                                                  mcast_src_ip='224.0.0.1')
        instance2.track_interfaces.append("eth4")

        if with_vips:
            vip_address1 = keepalived.KeepalivedVipAddress('192.168.3.0/24',
                                                           'eth6', track=False)

            instance2.vips.append(vip_address1)
            instance2.vips.append(vip_address2)
            instance2.vips.append(vip_address_ex)

        config.add_instance(instance1)
        config.add_instance(instance2)

        return config


class KeepalivedConfTestCase(KeepalivedBaseTestCase,
                             KeepalivedConfBaseMixin):

    expected = KEEPALIVED_GLOBAL_CONFIG + \
               KEEPALIVED_VR_1_CONFIG + \
               KEEPALIVED_VR_1_TRACK_IF + \
               KEEPALIVED_VR_1_VIP + \
               KEEPALIVED_VR_1_VIPEX_x4.format(notrk=NOTRACK) + \
               KEEPALIVED_VR_1_VRTS_A.format(notrk=NOTRACK) + \
               KEEPALIVED_VR_1_CLOSE + \
               KEEPALIVED_VR_2_CONFIG + \
               KEEPALIVED_VR_2_TRACK_IF + \
               KEEPALIVED_VR_2_VIP + \
               KEEPALIVED_VR_2_VIPEX.format(notrk=NOTRACK) + \
               KEEPALIVED_VR_2_CLOSE

    def test_config_generation(self):
        config = self._get_config()
        self.assertEqual(self.expected, config.get_config_str())

    def test_config_with_reset(self):
        config = self._get_config()
        self.assertEqual(self.expected, config.get_config_str())

        config.reset()
        self.assertEqual(KEEPALIVED_GLOBAL_CONFIG, config.get_config_str())

    def test_get_existing_vip_ip_addresses_returns_list(self):
        config = self._get_config()
        instance = config.get_instance(1)
        current_vips = sorted(instance.get_existing_vip_ip_addresses('eth2'))
        self.assertEqual(['192.168.2.0/24', '192.168.3.0/24'], current_vips)


class KeepalivedConfWithoutNoTrackTestCase(KeepalivedConfTestCase):

    expected = KEEPALIVED_GLOBAL_CONFIG + \
               KEEPALIVED_VR_1_CONFIG + \
               KEEPALIVED_VR_1_TRACK_IF + \
               KEEPALIVED_VR_1_VIP + \
               KEEPALIVED_VR_1_VIPEX_x4.format(notrk='') + \
               KEEPALIVED_VR_1_VRTS_A.format(notrk='') + \
               KEEPALIVED_VR_1_CLOSE + \
               KEEPALIVED_VR_2_CONFIG + \
               KEEPALIVED_VR_2_TRACK_IF + \
               KEEPALIVED_VR_2_VIP + \
               KEEPALIVED_VR_2_VIPEX.format(notrk='') + \
               KEEPALIVED_VR_2_CLOSE

    def setUp(self):
        super(KeepalivedConfWithoutNoTrackTestCase, self).setUp()
        cfg.CONF.set_override('keepalived_use_no_track', False)


class KeepalivedStateExceptionTestCase(KeepalivedBaseTestCase):
    def test_state_exception(self):
        invalid_vrrp_state = 'a seal walks'
        self.assertRaises(keepalived.InvalidInstanceStateException,
                          keepalived.KeepalivedInstance,
                          invalid_vrrp_state, 'eth0', 33,
                          ['169.254.192.0/18'])

        invalid_auth_type = 'into a club'
        instance = keepalived.KeepalivedInstance('MASTER', 'eth0', 1,
                                                 ['169.254.192.0/18'])
        self.assertRaises(keepalived.InvalidAuthenticationTypeException,
                          instance.set_authentication,
                          invalid_auth_type, 'some_password')


class KeepalivedInstanceRoutesTestCase(KeepalivedBaseTestCase):
    @classmethod
    def _get_instance_routes(cls):
        routes = keepalived.KeepalivedInstanceRoutes()
        default_gw_eth0 = keepalived.KeepalivedVirtualRoute(
            '0.0.0.0/0', '1.0.0.254', 'eth0')
        default_gw_eth1 = keepalived.KeepalivedVirtualRoute(
            '::/0', 'fe80::3e97:eff:fe26:3bfa/64', 'eth1')
        routes.gateway_routes = [default_gw_eth0, default_gw_eth1]
        extra_routes = [
            keepalived.KeepalivedVirtualRoute('10.0.0.0/8', '1.0.0.1'),
            keepalived.KeepalivedVirtualRoute('20.0.0.0/8', '2.0.0.2')]
        routes.extra_routes = extra_routes
        extra_subnets = [
            keepalived.KeepalivedVirtualRoute(
                '30.0.0.0/8', None, 'eth0', scope='link')]
        routes.extra_subnets = extra_subnets
        return routes

    def test_routes(self):
        routes = self._get_instance_routes()
        self.assertEqual(len(routes.routes), 5)

    def test_remove_routes_on_interface(self):
        routes = self._get_instance_routes()
        routes.remove_routes_on_interface('eth0')
        self.assertEqual(len(routes.routes), 3)
        routes.remove_routes_on_interface('eth1')
        self.assertEqual(len(routes.routes), 2)


class KeepalivedInstanceTestCase(KeepalivedBaseTestCase,
                                 KeepalivedConfBaseMixin):
    def test_get_primary_vip(self):
        instance = keepalived.KeepalivedInstance('MASTER', 'ha0', 42,
                                                 ['169.254.192.0/18'])
        self.assertEqual('169.254.0.42/24', instance.get_primary_vip())

    def _test_remove_addresses_by_interface(self, no_track_value):
        config = self._get_config()
        instance = config.get_instance(1)
        instance.remove_vips_vroutes_by_interface('eth2')
        instance.remove_vips_vroutes_by_interface('eth10')
        config.add_instance(instance)

        expected = KEEPALIVED_GLOBAL_CONFIG + \
            KEEPALIVED_VR_1_CONFIG + \
            KEEPALIVED_VR_1_TRACK_IF + \
            KEEPALIVED_VR_1_VIP + \
            KEEPALIVED_VR_1_VIPEX_x1.format(notrk=no_track_value) + \
            KEEPALIVED_VR_1_VRTS_A.format(notrk=no_track_value) + \
            KEEPALIVED_VR_1_CLOSE + \
            KEEPALIVED_VR_2_CONFIG + \
            KEEPALIVED_VR_2_TRACK_IF + \
            KEEPALIVED_VR_2_VIP + \
            KEEPALIVED_VR_2_VIPEX.format(notrk=no_track_value) + \
            KEEPALIVED_VR_2_CLOSE

        self.assertEqual(expected, config.get_config_str())

    def test_remove_addresses_by_interface_without_no_track(self):
        cfg.CONF.set_override('keepalived_use_no_track', False)
        self._test_remove_addresses_by_interface("")

    def test_build_config_no_vips(self):
        cfg.CONF.set_override('keepalived_use_no_track', False)
        config = self._get_config(with_vips=False)

        expected = KEEPALIVED_GLOBAL_CONFIG + \
            KEEPALIVED_VR_1_CONFIG + \
            KEEPALIVED_VR_1_TRACK_IF + \
            KEEPALIVED_VR_1_VIP + \
            KEEPALIVED_VR_1_VRTS_A.format(notrk='') + \
            KEEPALIVED_VR_1_CLOSE + \
            KEEPALIVED_VR_2_CONFIG + \
            KEEPALIVED_VR_2_TRACK_IF + \
            KEEPALIVED_VR_2_VIP + \
            KEEPALIVED_VR_2_CLOSE

        self.assertEqual(expected, config.get_config_str())

    def test_build_config_no_vips_track_script(self):
        config = keepalived.KeepalivedConf()

        expected = KEEPALIVED_GLOBAL_CONFIG + \
            KEEPALIVED_TRACK_SCRIPT + \
            KEEPALIVED_VR_1_CONFIG + \
            KEEPALIVED_VR_1_VIP + \
            KEEPALIVED_VR_2_CLOSE

        instance = keepalived.KeepalivedInstance(
            'MASTER', 'eth0', VRRP_ID, ['169.254.192.0/18'])
        instance.track_script = keepalived.KeepalivedTrackScript(
            VRRP_INTERVAL, '/etc/ha_confs/qrouter-x', VRRP_ID)
        config.add_instance(instance)
        self.assertEqual(expected, config.get_config_str())


class KeepalivedVipAddressTestCase(KeepalivedBaseTestCase):
    def test_vip_with_scope(self):
        vip = keepalived.KeepalivedVipAddress('fe80::3e97:eff:fe26:3bfa/64',
                                              'eth1',
                                              'link')
        self.assertEqual('fe80::3e97:eff:fe26:3bfa/64 dev eth1 scope link',
                         vip.build_config())

    def test_add_vip_idempotent(self):
        instance = keepalived.KeepalivedInstance('MASTER', 'eth0', 1,
                                                 ['169.254.192.0/18'])
        instance.add_vip('192.168.222.1/32', 'eth11', None)
        instance.add_vip('192.168.222.1/32', 'eth12', 'link')
        self.assertEqual(1, len(instance.vips))


class KeepalivedVirtualRouteTestCase(KeepalivedBaseTestCase):
    def test_virtual_route_with_dev(self):
        route = keepalived.KeepalivedVirtualRoute(n_consts.IPv4_ANY, '1.2.3.4',
                                                  'eth0')
        self.assertEqual('0.0.0.0/0 via 1.2.3.4 dev eth0 no_track',
                         route.build_config())

    def test_virtual_route_with_dev_without_no_track(self):
        cfg.CONF.set_override('keepalived_use_no_track', False)
        route = keepalived.KeepalivedVirtualRoute(n_consts.IPv4_ANY, '1.2.3.4',
                                                  'eth0')
        self.assertEqual('0.0.0.0/0 via 1.2.3.4 dev eth0',
                         route.build_config())

    def test_virtual_route_without_dev(self):
        route = keepalived.KeepalivedVirtualRoute('50.0.0.0/8', '1.2.3.4')
        self.assertEqual('50.0.0.0/8 via 1.2.3.4 no_track',
                         route.build_config())

    def test_virtual_route_without_dev_without_no_track(self):
        cfg.CONF.set_override('keepalived_use_no_track', False)
        route = keepalived.KeepalivedVirtualRoute('50.0.0.0/8', '1.2.3.4')
        self.assertEqual('50.0.0.0/8 via 1.2.3.4', route.build_config())


class KeepalivedTrackScriptTestCase(KeepalivedBaseTestCase):

    def test_get_config_str(self):
        cfg.CONF.set_override('keepalived_use_no_track', False)
        config = keepalived.KeepalivedConf()
        expected = KEEPALIVED_GLOBAL_CONFIG + \
            KEEPALIVED_TRACK_SCRIPT + \
            KEEPALIVED_VR_1_CONFIG + \
            KEEPALIVED_VR_1_VIP + \
            KEEPALIVED_VR_1_VRTS_B.format(notrk='') + \
            KEEPALIVED_VR_1_TRACK_SCRIPT + \
            KEEPALIVED_VR_2_CLOSE

        instance = keepalived.KeepalivedInstance(
            'MASTER', 'eth0', VRRP_ID, ['169.254.192.0/18'])
        instance.track_script = keepalived.KeepalivedTrackScript(
            VRRP_INTERVAL, '/etc/ha_confs/qrouter-x', VRRP_ID)
        instance.virtual_routes.gateway_routes = [
            keepalived.KeepalivedVirtualRoute('12.0.0.0/24', '10.0.0.1'), ]
        config.add_instance(instance)
        self.assertEqual(expected, config.get_config_str())

    def test_get_script_str(self):
        ts = keepalived.KeepalivedTrackScript(
            VRRP_INTERVAL, '/etc/ha_confs/qrouter-x', VRRP_ID)
        ts.routes = [
            keepalived.KeepalivedVirtualRoute('12.0.0.0/24', '10.0.0.1'), ]
        ts.vips = [
            keepalived.KeepalivedVipAddress('192.168.0.3/18', 'ha-xxx'), ]

        self.assertEqual("""#!/bin/bash -eu
ip a | grep 192.168.0.3 || exit 0
ping -c 1 -w 1 10.0.0.1 1>/dev/null || exit 1""",
                         ts._get_script_str())

    def test_get_script_str_no_routes(self):
        ts = keepalived.KeepalivedTrackScript(
            VRRP_INTERVAL, '/etc/ha_confs/qrouter-x', VRRP_ID)

        self.assertEqual('#!/bin/bash -eu\n', ts._get_script_str())

    def test_write_check_script(self):
        conf_dir = '/etc/ha_confs/qrouter-x'
        ts = keepalived.KeepalivedTrackScript(VRRP_INTERVAL, conf_dir, VRRP_ID)
        ts.routes = [
            keepalived.KeepalivedVirtualRoute('12.0.0.0/24', '10.0.0.1'),
            keepalived.KeepalivedVirtualRoute('2001:db8::1', '2001:db8::1'), ]
        with mock.patch.object(keepalived, 'file_utils') as patched_utils:
            ts.write_check_script()
            patched_utils.replace_file.assert_called_with(
                os.path.join(conf_dir, 'ha_check_script_1.sh'),
                """#!/bin/bash -eu

ping -c 1 -w 1 10.0.0.1 1>/dev/null || exit 1
ping6 -c 1 -w 1 2001:db8::1 1>/dev/null || exit 1""",
                0o520
            )

    def test_write_check_script_no_routes(self):
        conf_dir = '/etc/ha_confs/qrouter-x'
        ts = keepalived.KeepalivedTrackScript(
            VRRP_INTERVAL, conf_dir, VRRP_ID)
        with mock.patch.object(keepalived, 'file_utils') as patched_utils:
            ts.write_check_script()
            patched_utils.replace_file.assert_not_called()


class KeepalivedManagerTestCase(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.mock_config = mock.Mock()
        self.mock_config.AGENT.check_child_processes_interval = False
        self.process_monitor = external_process.ProcessMonitor(
            self.mock_config, mock.ANY)
        self.uuid = uuidutils.generate_uuid()
        self.process_monitor.register(
            self.uuid, keepalived.KEEPALIVED_SERVICE_NAME, mock.ANY)
        self.keepalived_manager = keepalived.KeepalivedManager(
            self.uuid, self.mock_config, self.process_monitor, mock.ANY)
        self.mock_get_process = mock.patch.object(self.keepalived_manager,
                                                  'get_process')

    def test_destroy(self):
        mock_get_process = self.mock_get_process.start()
        process = mock.Mock()
        mock_get_process.return_value = process
        process.active = False
        self.keepalived_manager.disable()
        process.disable.assert_called_once_with(
            sig=str(int(signal.SIGTERM)))

    def test_destroy_force(self):
        mock_get_process = self.mock_get_process.start()
        with mock.patch.object(keepalived, 'SIGTERM_TIMEOUT', 0):
            process = mock.Mock()
            mock_get_process.return_value = process
            process.active = True
            self.keepalived_manager.disable()
            process.disable.assert_has_calls([
                mock.call(sig=str(int(signal.SIGTERM))),
                mock.call(sig=str(int(signal.SIGKILL)))])
