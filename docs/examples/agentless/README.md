# Agentless Scanning Onboarding

This guide sets up Triton agentless scanning for a fleet of 1000+ hosts
and routers. Assumes you have Ansible for fleet management.

## 1. Scanner host setup (one-time, 10 min)

    # Install Triton
    sudo apt install triton

    # Generate the encryption key
    export TRITON_SCANNER_CRED_KEY=$(openssl rand -hex 32)
    echo "Save this key securely — losing it means losing credential access!"

    echo "export TRITON_SCANNER_CRED_KEY=$TRITON_SCANNER_CRED_KEY" | \
      sudo tee -a /etc/triton/env

    # Generate scanner SSH keypair
    sudo -E triton credential bootstrap --name prod-scanner

## 2. Deploy SSH access to 1000 hosts (5-10 min)

    ansible-playbook \
      -i your-inventory.yaml \
      triton-access.yaml \
      -e scanner_pubkey_file=/etc/triton/keys/prod-scanner.pub

## 3. Build devices.yaml

Copy `devices.yaml.example` to `/etc/triton/devices.yaml` and fill in
your hostnames, addresses, and credential names.

For large fleets, export from ServiceNow/AD/cloud inventory APIs.

## 4. Register credentials

    sudo -E triton credential add --name prod-ssh-key --type ssh-key \
      --username triton-scanner --key /etc/triton/keys/prod-scanner

    sudo -E triton credential add --name cisco-tacacs --type ssh-password \
      --username triton-readonly --password "$(cat /tmp/tacacs-pw)"

## 5. First scan

    # Dry run (validates connectivity without scanning)
    sudo -E triton network-scan --inventory /etc/triton/devices.yaml --dry-run

    # Real scan
    sudo -E triton network-scan --inventory /etc/triton/devices.yaml \
      --report-server https://reports.example.com

At default concurrency (20), 1000 devices finish in ~5 minutes.

## 6. Schedule via systemd

    # /etc/systemd/system/triton-netscan.service
    [Service]
    Type=oneshot
    ExecStart=/usr/bin/triton network-scan --inventory /etc/triton/devices.yaml
    EnvironmentFile=/etc/triton/env

    # /etc/systemd/system/triton-netscan.timer
    [Timer]
    OnCalendar=daily
    Persistent=true

    sudo systemctl enable --now triton-netscan.timer

## Troubleshooting

**Authentication failed for host X** — verify the user exists on target
and the credential name matches `triton credential list`.

**Cisco show command error** — verify the read-only user has
`privilege 5` or `role network-operator`.

**NETCONF authentication failed** — verify NETCONF is enabled on the
Juniper device (`show system services netconf`) and port 830 is reachable.
