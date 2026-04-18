# Fleet scan example

Minimal walkthrough of `triton fleet-scan`.

## 1. Inventory

Copy `/docs/examples/agentless/devices.yaml.example` to `/etc/triton/devices.yaml`. Add one entry per unix host:

```yaml
version: 1
defaults:
  port: 22
  sudo: true

devices:
  - name: web-srv-01
    type: unix
    address: 10.0.1.10
    credential: prod-ssh
```

## 2. Credentials

Credentials are stored encrypted via `triton credential` commands. Generate the encryption key:

```bash
export TRITON_SCANNER_CRED_KEY=$(openssl rand -hex 32)
triton credential add --name prod-ssh --username deploy --key-file ~/.ssh/prod_ed25519
```

## 3. SSH prerequisites on target hosts

- `deploy` user has SSH access via key
- `echo "deploy ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/triton-deploy`
- Known-hosts entry in `/etc/triton/known_hosts` (or pass `--insecure-host-key` for testing)

## 4. Run

```bash
triton fleet-scan --inventory /etc/triton/devices.yaml \
                  --credentials /etc/triton/credentials.yaml \
                  --known-hosts /etc/triton/known_hosts \
                  --output-dir ./scans/ --profile standard \
                  --max-memory 2GB --max-duration 4h
```

## 5. Inspect output

```bash
cat scans/latest/summary.txt
jq . scans/latest/summary.json
tar -tvf scans/latest/hosts/web-srv-01.tar.gz
```

## SSH agentless deployment (no persistent install)

The whole flow is binary-push + detach — nothing stays on the target after `--cleanup`. This is the SSH-agentless pattern: no long-running service, no manual install, just your inventory and an SSH key.
