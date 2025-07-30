from pathlib import Path
from json import load as json_load

TESTDATA_DIR = Path(__file__).parent / 'testdata'


def test_1():
    with open(TESTDATA_DIR / 'ruleset.json', 'r', encoding='utf-8') as f:
        ruleset = json_load(f)
    
    firewall = Firewall(ruleset)
    
    with open(TESTDATA_DIR / 'routes.json', 'r', encoding='utf-8') as f:
        routes = json_load(f)
    
    with open(TESTDATA_DIR / 'routes.interfaces', 'r', encoding='utf-8') as f:
        interfaces = json_load(f)
    
    with open(TESTDATA_DIR / 'rules.json', 'r', encoding='utf-8') as f:
        rules = json_load(f)
    
    router = Router(interfaces, routes, rules)
    
    simulator = Simulator(firewall, router)
    
    packets = [
        Packet('10.0.50.11', '10.0.40.13'),
        Packet('10.0.40.13', '10.0.50.11'),
        Packet('10.0.50.11', '10.0.20.10'),
    ]
    
    for packet in packets:
        assert simulator.simulate(packet) == 'accept'
