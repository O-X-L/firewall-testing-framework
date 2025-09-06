# Firewall Testing-Framework

[![Lint](https://github.com/O-X-L/firewall-testing-framework/actions/workflows/lint.yml/badge.svg?branch=latest)](https://github.com/O-X-L/firewall-testing-framework/actions/workflows/lint.yml)
[![Test](https://github.com/O-X-L/firewall-testing-framework/actions/workflows/test.yml/badge.svg?branch=latest)](https://github.com/O-X-L/firewall-testing-framework/actions/workflows/test.yml)
[![Test Entrypoints](https://github.com/O-X-L/firewall-testing-framework/actions/workflows/entrypoints.yml/badge.svg?branch=latest)](https://github.com/O-X-L/firewall-testing-framework/actions/workflows/entrypoints.yml)

A framework for **testing and troubleshooting firewall rulesets**.

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
        --src-ip 10.0.0.1 \
        --dst-ip 172.17.10.6

> 🛈 ROUTER: Packet inbound-interface: wan
> 🛈 ROUTER: Packet inbound-route: 0.0.0.0/0, gw 10.255.255.254, metric 600, scope remote
> 🛈 FIREWALL: Processing Chain: Table nat ip4 | Chain PREROUTING ip4 nat
> 🛈 FIREWALL: > Chain PREROUTING | Rule 0 | Match => jump
> 🛈 FIREWALL: > Chain PREROUTING | Sub-Chain: DOCKER
> 🛈 FIREWALL: > Chain DOCKER | Rule 0
> 🛈 FIREWALL: > Chain DOCKER | Rule 1
> 🛈 ROUTER: Packet outbound-interface: docker0
> 🛈 ROUTER: Packet outbound-route: 172.17.0.0/16, scope link
> 🛈 FIREWALL: Processing Chain: Table filter ip4 | Chain FORWARD ip4 filter
> 🛈 FIREWALL: > Chain FORWARD | Rule 0 | Match => jump
> 🛈 FIREWALL: > Chain FORWARD | Sub-Chain: DOCKER-USER
> 🛈 FIREWALL: > Chain DOCKER-USER | Rule 0 | Match => return
> 🛈 FIREWALL: > Chain FORWARD | Rule 1 | Match => jump
> 🛈 FIREWALL: > Chain FORWARD | Sub-Chain: DOCKER-FORWARD
> 🛈 FIREWALL: > Chain DOCKER-FORWARD | Rule 0 | Match => jump
> 🛈 FIREWALL: > Chain DOCKER-FORWARD | Sub-Chain: DOCKER-CT
> 🛈 FIREWALL: > Chain DOCKER-CT | Rule 0 | Match => accept
> 🛈 FIREWALL: > Chain DOCKER-FORWARD | Rule 1 | Match => jump
> 🛈 FIREWALL: > Chain DOCKER-FORWARD | Sub-Chain: DOCKER-ISOLATION-STAGE-1
> 🛈 FIREWALL: > Chain DOCKER-ISOLATION-STAGE-1 | Rule 0
> 🛈 FIREWALL: > Chain DOCKER-FORWARD | Rule 2 | Match => jump
> 🛈 FIREWALL: > Chain DOCKER-FORWARD | Sub-Chain: DOCKER-BRIDGE
> 🛈 FIREWALL: > Chain DOCKER-BRIDGE | Rule 0 | Match => jump
> 🛈 FIREWALL: > Chain DOCKER-BRIDGE | Sub-Chain: DOCKER
> 🛈 FIREWALL: > Chain DOCKER | Rule 0
> 🛈 FIREWALL: > Chain DOCKER | Rule 1 | Match => drop
> ✖ FIREWALL: Packet blocked by rule: {'action': 'drop', 'seq': 1, 'raw': Rule: #22 | Matches: [ni_in != ['docker0'], ni_out == ['docker0']]}

```

----

## Roadmap

### 2025

**Core Simulator**:
- [ ] Fundamental Features
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
- [ ] Run modes:
  - [x] One-Shot CLI
  - [ ] Basic interactive shell
  - [ ] Automated/CI mode
    - [ ] Run multiple Test-cases from config
- [ ] Defining basic config-schema (Topology, Rulesets, Tests)
- [ ] Option to Output results to JSON
- [ ] Supporting multiple Firewalls
  - [ ] Generating Layer 3 Topology
  - [ ] Detect Firewall-chaining (one firewall routes to another one - p.e. over VPN)

**Development**:
- [ ] Create Plugin Templates
- [ ] Create Guide on how to develop Plugins

**[Firewall Support](https://ftf.oxl.app/usage/2_system_support.html)**:
- [x] Netfilter (NFTables/IPTables)
- [ ] OPNsense (Information from Config-Backup-File and runtime-infos like routes from API)

----

## Contribute

See: [CONTRIBUTING](https://github.com/O-X-L/firewall-testing-framework/blob/latest/CONTRIBUTING.md)

----

## Credits

* Thanks to the [go-ftw (Web Application Firewall Testing Framework) project](https://github.com/coreruleset/go-ftw) that inspired us to create this project

* Thanks go to [@MikPisula](https://github.com/MikPisula) for some inspiration on how to simulate network-traffic over a firewall ([MikPisula/packet-simulator](https://github.com/MikPisula/packet-simulator))
