# ABAC Tools

## mac_abac_ctl

CLI for managing labels, rules, and monitoring.

### Label Management

```sh
mac_abac_ctl label get /path/to/file
mac_abac_ctl label set /path/to/file "type=trusted,domain=web"
mac_abac_ctl label remove /path/to/file
```

### Rule Management

```sh
mac_abac_ctl rule add "deny exec * -> type=untrusted"
mac_abac_ctl rule list
mac_abac_ctl rule remove 5
mac_abac_ctl rule clear
mac_abac_ctl rule load /etc/mac_abac/rules.conf   # Atomic replace
```

### Mode and Stats

```sh
mac_abac_ctl mode                    # Get current mode
mac_abac_ctl mode enforcing          # Set mode
mac_abac_ctl stats                   # Show statistics
mac_abac_ctl limits                  # Show kernel limits
```

### Monitoring

```sh
mac_abac_ctl monitor                 # Watch audit events in real-time
```

## mac_abacd

Policy daemon that loads rules from config files.

```sh
mac_abacd -c /etc/mac_abac/policy.conf      # Run daemon
mac_abacd -t -c /etc/mac_abac/policy.conf   # Test config syntax
mac_abacd -d -c /etc/mac_abac/policy.conf   # Debug mode (foreground)
```

Send `SIGHUP` to reload config:
```sh
kill -HUP $(cat /var/run/mac_abacd.pid)
```

## Sysctls

```sh
sysctl security.mac.mac_abac.mode=2           # Set enforcing
sysctl security.mac.mac_abac.default_policy=1 # Default deny
sysctl security.mac.mac_abac                  # Show all
```
