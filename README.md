# Firewall Testing-Framework

[![Lint](https://github.com/O-X-L/firewall-testing-framework/actions/workflows/lint.yml/badge.svg?branch=latest)](https://github.com/O-X-L/firewall-testing-framework/actions/workflows/lint.yml)
[![Test](https://github.com/O-X-L/firewall-testing-framework/actions/workflows/test.yml/badge.svg?branch=latest)](https://github.com/O-X-L/firewall-testing-framework/actions/workflows/test.yml)

A framework for **testing and troubleshooting firewall rulesets**.

----

## Documentation

You can find the documentation at: [ftf.oxl.app](https://ftf.oxl.app)

<img src="https://raw.githubusercontent.com/O-X-L/firewall-testing-framework/refs/heads/latest/docs/source/_static/img/topology.svg" max-width="700"></img>

----

## Roadmap

### 2025

**Core Simulator**:
- [ ] Fundamental Features
  - [x] Routing
  - [x] Network Interfaces
  - [x] Firewall Tables
  - [x] Firewall Chains
  - [x] Firewall Rules
  - [x] System-Specific Translate-Plugins
  - [x] System-Specific Rule-Matching
- [ ] Run modes:
  - [x] One-Shot CLI
  - [ ] Basic interactive shell
  - [ ] Automated/CI mode
    - [ ] Run multiple Test-cases from config (CLI pytest-like?)
- [ ] Defining basic config-schema (Topology, Rulesets, Tests)
- [ ] Option to Output results to JSON
- [ ] Supporting multiple Firewalls
  - [ ] Generating Layer 3 Topology
  - [ ] Detect Firewall-chaining (one firewall routes to another one - p.e. over VPN)

**Development**:
- [ ] Create Plugin Templates
- [ ] Create Guide on how to develop Plugins

**Firewall Support**:
- [ ] Netfilter (NFTables/IPTables)
- [ ] OPNsense (Information from Config-Backup-File and runtime-infos like routes from API)

----

## Contribute

See: [CONTRIBUTING](https://github.com/O-X-L/firewall-testing-framework/blob/latest/CONTRIBUTING.md)

----

## Credits

* Thanks to the [go-ftw (Web Application Firewall Testing Framework) project](https://github.com/coreruleset/go-ftw) that inspired us to create this project

* Thanks go to [@MikPisula](https://github.com/MikPisula) for some inspiration on how to simulate network-traffic over a firewall ([MikPisula/packet-simulator](https://github.com/MikPisula/packet-simulator))
