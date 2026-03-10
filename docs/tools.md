# vLabel Tools

## vlabelctl

CLI for managing labels, rules, and monitoring.

### Label Management

```sh
vlabelctl label get /path/to/file
vlabelctl label set /path/to/file "type=trusted,domain=web"
vlabelctl label remove /path/to/file
```

### Rule Management

```sh
vlabelctl rule add "deny exec * -> type=untrusted"
vlabelctl rule list
vlabelctl rule remove 5
vlabelctl rule clear
vlabelctl rule load /etc/vlabel/rules.conf   # Atomic replace
```

### Mode and Stats

```sh
vlabelctl mode                    # Get current mode
vlabelctl mode enforcing          # Set mode
vlabelctl stats                   # Show statistics
vlabelctl limits                  # Show kernel limits
```

### Monitoring

```sh
vlabelctl monitor                 # Watch audit events in real-time
```

## vlabeld

Policy daemon that loads rules from config files.

```sh
vlabeld -c /etc/vlabel/policy.conf      # Run daemon
vlabeld -t -c /etc/vlabel/policy.conf   # Test config syntax
vlabeld -d -c /etc/vlabel/policy.conf   # Debug mode (foreground)
```

Send `SIGHUP` to reload config:
```sh
kill -HUP $(cat /var/run/vlabeld.pid)
```

## Sysctls

```sh
sysctl security.mac.vlabel.mode=2           # Set enforcing
sysctl security.mac.vlabel.default_policy=1 # Default deny
sysctl security.mac.vlabel                  # Show all
```
