# Firewall Testing-Framework

[![Lint](https://github.com/O-X-L/firewall-testing-framework/actions/workflows/lint.yml/badge.svg?branch=latest)](https://github.com/O-X-L/firewall-testing-framework/actions/workflows/lint.yml)
[![Test](https://github.com/O-X-L/firewall-testing-framework/actions/workflows/test.yml/badge.svg?branch=latest)](https://github.com/O-X-L/firewall-testing-framework/actions/workflows/test.yml)
[![Test Entrypoints](https://github.com/O-X-L/firewall-testing-framework/actions/workflows/entrypoints.yml/badge.svg?branch=latest)](https://github.com/O-X-L/firewall-testing-framework/actions/workflows/entrypoints.yml)

A framework for **testing and troubleshooting firewall rulesets**.

[Module on pypi.org](https://pypi.org/project/firewall-test/)

<img src="https://raw.githubusercontent.com/O-X-L/firewall-testing-framework/refs/heads/latest/docs/source/_static/img/opnsense.gif" alt="Intro GIF" width="70%"/>

----

## Documentation

You can find the documentation at: [ftf.oxl.app](https://ftf.oxl.app)

<img src="https://raw.githubusercontent.com/O-X-L/firewall-testing-framework/refs/heads/latest/docs/source/_static/img/topology.svg" max-width="700"></img>

----

## CLI Example

For more see: [ftf.oxl.app - Usage - Run](https://ftf.oxl.app/usage/3_run.html)

```bash
ftf-cli --firewall-system 'linux_netfilter' \
        --file-interfaces 'testdata/plugin_translate_linux_interfaces.json' \
        --file-routes 'testdata/plugin_translate_linux_routes.json' \
        --file-route-rules 'testdata/plugin_translate_linux_route-rules.json' \
        --file-ruleset 'testdata/plugin_translate_netfilter_ruleset.json' \
        --src-ip 172.17.11.5 \
        --dst-ip 2.2.2.2

> 🛈 SYSTEM: Processing packet: [172.17.11.5]:50000 =tcp=> [2.2.2.2]:443
> 🛈 ROUTER: Packet inbound-interface: docker0
> 🛈 ROUTER: Packet inbound-route: 172.17.0.0/16, scope link
> 🛈 FIREWALL: Processing Chain: Table "nat" ip4 | Chain "PREROUTING" ip4 nat (1 rules)
> 🛈 FIREWALL: > Chain PREROUTING | Rule 0 | Match => jump
> 🛈 FIREWALL: > Chain PREROUTING | Sub-Chain: DOCKER (2 rules)
> 🛈 FIREWALL: > Chain DOCKER | Rule 0 | Match => return
> 🛈 ROUTER: Packet outbound-interface: wan
> 🛈 ROUTER: Packet outbound-route: 0.0.0.0/0, gw 10.255.255.254, metric 600, scope global
> 🛈 FIREWALL: Processing Chain: Table "filter" ip4 | Chain "FORWARD" ip4 filter (5 rules)
> 🛈 FIREWALL: > Chain FORWARD | Rule 0 | Match => jump
> 🛈 FIREWALL: > Chain FORWARD | Sub-Chain: DOCKER-USER (1 rules)
> 🛈 FIREWALL: > Chain DOCKER-USER | Rule 0 | Match => return
> 🛈 FIREWALL: > Chain FORWARD | Rule 1 | Match => drop
> ✖ FIREWALL: Packet blocked by rule: Seq 1, Action: drop, Rule: #101 "TEST IP4-DADDR DROP"
>              > Matches: {'proto_l3': {'==': 'ip4'}, 'ip_daddr': {'==': ['2.2.2.2/32']}}
```

----

## Roadmap

### 2025

**Core Simulator**:
- [x] Fundamental Features
  - [x] Routing
  - [x] Network Interfaces
  - [x] Firewall Tables
  - [x] Firewall Chains
    - [x] Sub-Chains (Jump, Goto)
  - [x] Firewall Rules
  - [x] System-Specific Translate-Plugins
  - [x] System-Specific Rule-Matching
  - [x] Destination-NAT
  - [x] Source-NAT
- [x] Run modes:
  - [x] One-Shot CLI

**[Firewall Support](https://ftf.oxl.app/usage/2_system_support.html)**:
- [x] Netfilter (NFTables/IPTables)
- [x] OPNsense

### 2026

**Core Simulator**:
- [ ] Run modes:
  - [ ] Basic interactive shell
  - [ ] Automated/CI mode
    - [ ] Run multiple Test-cases from config
    - [ ] Defining basic config-schema (Topology, Rulesets, Tests)
- [ ] API
  - [ ] Option to Output results to JSON
  - [ ] Create & document API for integration by other tools
- [ ] Supporting multiple Firewalls
  - [ ] Generating Layer 3 Topology
  - [ ] Detect Firewall-chaining (one firewall routes to another one - p.e. over VPN)

**Development**:
- [ ] Create Plugin Templates
- [ ] Create Guide on how to develop Plugins

**[Firewall Support](https://ftf.oxl.app/usage/2_system_support.html)**:
- [x] Netfilter (NFTables/IPTables)
- [ ] OPNsense

----

## Contribute

Feel welcome to contribute to this project. (:

See: [CONTRIBUTING](https://github.com/O-X-L/firewall-testing-framework/blob/latest/CONTRIBUTING.md)

----

## Credits

* Thanks to the [go-ftw (Web Application Firewall Testing Framework) project](https://github.com/coreruleset/go-ftw) that inspired us to create this project

* Thanks go to [@MikPisula](https://github.com/MikPisula) for some inspiration on how to simulate network-traffic over a firewall ([MikPisula/packet-simulator](https://github.com/MikPisula/packet-simulator))
