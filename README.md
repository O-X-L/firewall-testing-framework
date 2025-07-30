# Firewall Testing-Framework

A framework for testing and troubleshooting firewall Layer 3-4 rulesets.

**WARNING**: This project is still in the conception-phase.

----

## Goal / Why?

When having to administer IT infrastructure and networks - we will often have multiple firewalls in place.

Maintaining these might be time-consuming. You might also face some challenges:

* **Troubleshooting & Analysis**:

  Even for senior network engineers it can be a challenge to find the source of an unexpected block/accept in large rulesets that are distributed across multiple systems and firewall vendors. 

  Infrastructure-as-Code does help to keep the rulesets in a consistent state - but it does not solve the issue of having to manually analyze/troubleshoot existing rulesets.

  This project wants to provide one interface for simulating traffic over multiple firewall systems.

* **Automated Regression-Tests**:

  Why would you want to do ruleset-regression-tests?
  * If you utilize Infrastructure-as-Code and change-reviews for updating your ruleset you might want to 
  * You may want/need to periodically verify that the currently active rulesets actually allow/deny the traffic you expect
    This can be a tedious task - you might overlook some edge-case.
  * Especially when a ruleset is administered by teams of engineers over a long time period - it can be a challenge to:
    * detect configuration errors/mistakes before they can be exploited
    * make sure the design-choices for the ruleset are adhered to

  How do regression-tests work?
  * You define test-cases that simulate traffic over one or multiple firewalls
  * You assert that the traffic was allowed/denied/rejected
  * You might even want to assert that the traffic took a specific outbound route or was NATed to a specific IP

  This way you can continuously extend these test-cases and easily verify that the currently active rulesets comply with them.

----

## Idea

Take a look at this topology:

<img src="https://raw.githubusercontent.com/O-X-L/firewall-testing-framework/refs/heads/latest/docs/source/_static/img/topology.svg" max-width="700"></img>

The flow is planned to be:

1. Either:
  * manually pull the current config from the existing firewalls
  * or utilize existing `pull-plugins` to do so (p.e. via API)

2. The vendor-specific configuration gets parsed by `translation-plugins` which output a standardized firewall config-schema.

3. The user provides a high-level `topology-config`

4. If automated tests should be run: The user needs to provide a `test-traffic config`

  Else the user has the option to enter an interactive shell where traffic can be sent manually

5. The `firewall/network simulator`

  * parses the provided config
  * generates the network-topology
  * finds where the packet originates from (or notifies the user if more information is required)
  * finds the route the packet should take
  * tests the traffic against the rulesets of firewalls that are hops of that route

Thanks already go to @MikPisula, the creator of the [MikPisula/packet-simulator](https://github.com/MikPisula/packet-simulator) for creating a simulator for netfilter (IPTables/NFTables) firewalls.

Also thanks to the [go-ftw (Web Application Firewall Testing Framework) project](https://github.com/coreruleset/go-ftw) that inspired us to support regression-tests.

----

## Principles

* **Strict separation of vendor-specific plugins** from the core traffic-simulator. 

  Plugins CAN be used to pull the current configuration (rulesets, interfaces, routes) from a firewall system, but admins should always be able to manually provide this information.

  Some might not want to trust some 'nice-to-have' tool with access to their firewalls.

* The user should be able to choose the **output verbosity**.

  We want to provide full transparency (*show every rule the traffic interacts with*) but if not required (*p.e in automated/CI-mode*) it should be brief.

----

## Contribute

Contributions are welcome (:

What would be helpful for now:
* Feel free to discuss the ideas and roadmap for this project with us: [GitHub discussions](https://github.com/O-X-L/firewall-testing-framework/discussions) or [contact us directly](mailto://contact@oxl.at)
* Open [issues](https://github.com/O-X-L/firewall-testing-framework/issues) if you think you have found a problem with the existing code (be aware that it might not yet be in a usable state)

* Please do not post any generic AI-slop.. thanks.
* Be friendly and respectful

----

## Roadmap

### 2025

**Core Simulator**:
* Generating Layer 3 Topology
* Generating multiple Firewalls
* Detect Firewall-chaining (one firewall routes to another one - p.e. over VPN)
* Run modes:
  * Basic interactive shell
  * Automated/CI mode
* Defining basic config-schema (Topology, Rulesets, Tests)
* Run multiple Test-cases from config (CLI pytest-like?)
* Option to Output results to JSON
* Security Features to protect users:
  * Warn before executing non-verified (code review) plugin

**Development**:
* Create Plugin Templates
* Create Guide on how to develop Plugins

**Firewall Support**:
* Netfilter (NFTables/IPTables)
* OPNsense (Plugin that parses Config-Backup-File)

----

### What will be out-of-scope for now

Why? Because we initially need to focus on building the core simulator!

* Transparent firewalls (layer 2 interception)
* Application-Level Protocols
* Connection-Tracking helpers (rules that use these CT-states)
* Non-static routing (dynamic routing, rule-based routing via fwmark and routing-table lookup)
