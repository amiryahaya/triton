# Manage Server: Hosts

The Hosts view in the Manage Server portal provides inventory and lifecycle management for target hosts and scan endpoints. Hosts are central to the compliance scanning workflow — a Scan Job cannot run without selecting at least one host.

## Host Properties

Each host record contains the following properties:

| Property | Type | Required | Notes |
|----------|------|----------|-------|
| Hostname | String | Yes | FQDN or short name (e.g., `prod-db-01.example.com` or `workstation`) |
| IP Address | String | Yes | IPv4 or IPv6 address; must be unique per Manage Server instance |
| OS | Enum | No | Windows, Linux, macOS, Unix, Other; hints UI about available credential types |
| SSH Port | Integer | No | Default 22; valid range 1–65535; used for SSH-based scans |
| Tags | List | No | Zero or more tags for filtering and targeting (see [Tag System](#tag-system)) |
| Credentials | List | No | SSH keys, passwords, Windows domain creds (see [Credentials](#credentials)) |

## Adding Hosts

### Manual Entry

Click **+ New Host** on the Hosts page to open the form. Fill in required fields (Hostname, IP Address), optionally set OS, SSH Port, select tags, and choose credentials. Click **Add** to save.

### Bulk CSV Import

For large inventories, use **Import CSV** to add multiple hosts at once.

**CSV Format:**
```
hostname,ip_address,os,ssh_port,tags,credentials
prod-db-01,10.0.1.100,Linux,22,production;database,ssh-prod-key
prod-api-02,10.0.1.101,Linux,22,production;web,ssh-prod-key
staging-web-01,10.0.2.50,Windows,,staging;web,win-admin-cred
dev-laptop-01,192.168.1.10,macOS,,development;laptop,
```

**Import Rules:**

- **hostname** (required): Non-empty string
- **ip_address** (required): Valid IPv4 or IPv6; must not already exist in the system
- **os** (optional): One of `Windows`, `Linux`, `macOS`, `Unix`, `Other` (case-insensitive); defaults to empty
- **ssh_port** (optional): Integer 1–65535; defaults to 22 if blank
- **tags** (optional): Semicolon-separated list of tag names (e.g., `production;database;critical`); leading/trailing whitespace stripped; unknown tags are created on-the-fly
- **credentials** (optional): Credential name to attach; must exist or the import will fail for that row
- **Duplicate detection**: If hostname + IP already exist, the row is skipped with a warning; use **Replace** to overwrite the existing record

**Download Template:**
Click **Download CSV Template** to get a blank `.csv` file with headers for offline preparation.

### JSON Import

(Optional) For integration workflows, POST to `/api/v1/admin/hosts/import` with JSON array:

```json
[
  {
    "hostname": "prod-db-01",
    "ip_address": "10.0.1.100",
    "os": "Linux",
    "ssh_port": 22,
    "tags": ["production", "database"],
    "credentials": ["ssh-prod-key"]
  }
]
```

### Network Discovery

Use the **Discovery** tab to scan network ranges (CIDR) and auto-populate the Hosts inventory. See [Network Discovery guide](MANAGE_SERVER_DISCOVERY.md) for workflow details.

## Tag System

Tags serve two critical functions:

1. **Filtering**: Filter the Hosts list by tag (e.g., show only production hosts)
2. **Scan Job Targeting**: Only hosts with at least one tag can be selected in a Scan Job. Hosts without tags appear with a ⚠️ **No Tags** warning badge and cannot be targeted.

### Built-in Tags

The Manage Server includes 13 built-in tags, each with a color and purpose:

| Tag | Color | Purpose |
|-----|-------|---------|
| production | #EF4444 (Red) | Production environment |
| staging | #F97316 (Orange) | Staging / pre-prod environment |
| development | #22C55E (Green) | Development environment |
| web | #3B82F6 (Blue) | Web / HTTP servers |
| database | #8B5CF6 (Purple) | Database servers |
| windows | #0EA5E9 (Cyan) | Windows hosts |
| linux | #15803D (Dark Green) | Linux hosts |
| unix | #4B5563 (Gray) | Unix (non-Linux) hosts |
| server | #1D4ED8 (Dark Blue) | Physical or virtual servers |
| laptop | #0891B2 (Teal) | Developer laptops / endpoints |
| workstation | #7C3AED (Violet) | User workstations |
| critical | #DC2626 (Dark Red) | High-priority compliance targets |
| pqc-scope | #F59E0B (Amber) | In-scope for PQC assessment |

**Custom Tags:** You can create additional tags beyond the 13 built-in ones. They will use a default color unless customized.

## Filtering

Use the **Tag Filter** dropdown (top-right of the Hosts table) to show only hosts with specific tags. Multi-select is supported; hosts matching *any* selected tag will appear.

## Credentials

Each host can be associated with one or more credentials used during scanning (SSH keys, passwords, Windows domain creds). Credentials must be created and managed separately in the **Credentials** section.

See [MANAGE_SERVER_CREDENTIALS.md](MANAGE_SERVER_CREDENTIALS.md) for detailed credential workflow, supported types, and security best practices.

## FAQ

### Q: A host was imported from network discovery but has no hostname, only an IP address. Can I scan it?

Yes. The IP address is sufficient for scanning. Edit the host to add a hostname (FQDN or alias) for easier reference, but it is not required. The system will label it "IP-only host" in the UI.

### Q: A Scan Job says "No hosts match the current filter." Why?

This occurs when:
1. **No hosts have tags**: Select hosts and add at least one tag each in the Hosts view
2. **Tag mismatch**: The Scan Job's tag filter does not overlap with any host's tags
3. **Empty inventory**: No hosts exist in the system yet; add hosts first

### Q: Why is bulk-delete not available for hosts?

Bulk-delete is intentionally disabled to prevent accidental mass loss of scan targets and credential bindings. Delete hosts individually via the host detail view, or contact an admin if you need to reset the entire inventory.
