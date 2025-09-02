# Testdata creation

## Plugins

### Linux

#### Translate - Routes

```
ip -j route show table all | jq > routes.json
ip -j rule show | jq > route-rules.json
```

To add another routing table:
* Add it to this file: `sudo nano /etc/iproute2/rt_tables`  (on debian - might differ on other systems)

  Per example: `99 test`

* Restart networking: `systemctl restart networking`  (on debian - might differ on other systems)
* Add a routing-rule: `sudo ip rule add from 172.18.0.0/16 table test`
* Add a route: `sudo ip route add 7.7.7.0/29 via 10.255.255.254 dev wan table test`

#### Translate - Interfaces

```
ip -j address show | jq > interfaces.json
```

----

### Netfilter

#### Translate - Ruleset

```
sudo nft -j list ruleset | jq > ruleset.json
```
