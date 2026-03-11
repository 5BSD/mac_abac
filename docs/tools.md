# ABAC Tools

## mac_abac_ctl

CLI for managing labels, rules, and monitoring.

### Label Management

```sh
mac_abac_ctl label get /path/to/file
mac_abac_ctl label set /path/to/file "type=trusted,domain=web"
mac_abac_ctl label setatomic /path/to/file "type=trusted"  # Single kernel syscall
mac_abac_ctl label setrecursive /path/dir "type=data" [-v] [-d|-f]
mac_abac_ctl label refresh /path/to/file    # Re-read cached label from extattr
mac_abac_ctl label remove /path/to/file
```

### Rule Management

```sh
mac_abac_ctl rule add "deny exec * -> type=untrusted"
mac_abac_ctl rule add -s 100 "allow read domain=web -> domain=web"  # Add to set 100
mac_abac_ctl rule list
mac_abac_ctl rule remove 5
mac_abac_ctl rule clear
mac_abac_ctl rule load /etc/mac_abac/rules.conf       # Atomic replace
mac_abac_ctl rule load -s 100 /etc/mac_abac/web.conf  # Load to set 100
mac_abac_ctl rule append /etc/mac_abac/extra.conf     # Append rules
mac_abac_ctl rule validate /etc/mac_abac/rules.conf   # Check syntax only
```

### Rule Sets

```sh
mac_abac_ctl set list                # Show set status (default 0-31)
mac_abac_ctl set list 0-100          # Show sets 0-100
mac_abac_ctl set enable 100          # Enable set 100
mac_abac_ctl set disable 100-200     # Disable sets 100-200
mac_abac_ctl set swap 0 50000        # Atomic swap for hot-reload
mac_abac_ctl set move 100 200        # Move rules between sets
mac_abac_ctl set clear 100           # Clear all rules in set
```

### Mode, Stats, and Policy Protection

```sh
mac_abac_ctl mode                    # Get current mode
mac_abac_ctl mode enforcing          # Set mode
mac_abac_ctl default                 # Get default policy
mac_abac_ctl default deny            # Set default deny
mac_abac_ctl status                  # Show mode, default, rule count
mac_abac_ctl stats                   # Show statistics
mac_abac_ctl limits                  # Show kernel limits
mac_abac_ctl log                     # Get log level
mac_abac_ctl log deny                # Log denials (none|error|admin|deny|all)
mac_abac_ctl lock                    # Lock policy until reboot
```

### Testing

```sh
mac_abac_ctl test exec "domain=user" "type=trusted"  # Test access
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
