from pathlib import Path

_dir = Path(__file__).parent.parent.parent / 'testdata'
TESTDATA_FILE_ROUTES = _dir / 'plugin_translate_linux_routes.json'
TESTDATA_FILE_ROUTE_RULES = _dir / 'plugin_translate_linux_route-rules.json'
TESTDATA_FILE_NIS = _dir / 'plugin_translate_linux_interfaces.json'
TESTDATA_FILE_NF_RULESET = _dir / 'plugin_translate_netfilter_ruleset.json'
TESTDATA_FILE_OPN_CONFIG = _dir / 'plugin_translate_opnsense_config.xml'
TESTDATA_FILE_OPN_NETWORK = _dir / 'plugin_translate_opnsense_network.json'

# IPs of the linux-netfilter system we use to test the core functionality
TEST_WAN_IP4 = '10.255.255.48'
TEST_WAN_IP6 = '2001:4bc9:1f9a:cfe6:aaaa:11e2:5f14:1793'

TEST_DST_IP4_DROP = '2.2.2.2'
TEST_DST_IP4_REJECT = '3.3.3.3'
TEST_DST_IP4_ACCEPT = '4.4.4.4'

TEST_DST_IP6_DROP = '2003:beef::1'
TEST_DST_IP6_REJECT = '2003:beef::2'
TEST_DST_IP6_ACCEPT = '2003:beef::3'
