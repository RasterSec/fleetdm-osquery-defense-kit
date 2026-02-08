# osquery-defense-kit FleetDM Converter

Automatically converts [Chainguard's osquery-defense-kit](https://github.com/chainguard-dev/osquery-defense-kit) queries to FleetDM-compatible YAML format.

## Features

- Tracks upstream osquery-defense-kit as a Git submodule
- Go-based converter parses SQL files and generates FleetDM YAML
- GitHub Actions CI/CD automatically regenerates queries on changes
- Weekly automated updates to stay current with upstream

## Quick Start

### Download pre-built YAML (easiest)

Download the latest release from the [Releases page](../../releases/latest):

- `chainguard-all.yml` - All queries combined
- `chainguard-detection.yml` - Threat detection queries
- `chainguard-incident-response.yml` - Incident response queries
- `chainguard-policy.yml` - Security policy queries

Then import to FleetDM:

```bash
fleetctl apply -f chainguard-all.yml
```

### Build from source

Clone with submodules

```bash
git clone --recurse-submodules https://github.com/RasterSec/fleetdm-osquery-defense-kit.git
cd fleetdm-osquery-defense-kit
```

### Build and convert

```bash
make
```

Generated FleetDM YAML files will be in `output/`:
- `chainguard-detection.yml` - Threat detection queries
- `chainguard-incident-response.yml` - Incident response queries
- `chainguard-policy.yml` - Security policy queries
- `chainguard-all.yml` - All queries combined

### Import to FleetDM

```bash
fleetctl apply -f output/chainguard-detection.yml
fleetctl apply -f output/chainguard-policy.yml
fleetctl apply -f output/chainguard-incident-response.yml
```

Or import everything at once:

```bash
fleetctl apply -f output/chainguard-all.yml
```

## Updating

### Manual update

```bash
make update
```

This updates the submodule to the latest upstream commit and regenerates the YAML files.

### Automatic updates

The repository includes GitHub Actions workflows that:

1. **Weekly submodule update** - Checks for new upstream commits and creates a PR
2. **Automatic releases** - Creates a new GitHub release when the submodule is updated

This means the [Releases page](../../releases) always has up-to-date FleetDM YAML files ready to download.

## Project Structure

```
.
├── cmd/convert/          # Go converter tool
├── upstream/             # osquery-defense-kit submodule
├── output/               # Generated FleetDM YAML files
├── .github/workflows/    # CI/CD workflows
├── Makefile
└── README.md
```

## Development

### Prerequisites

- Go 1.22+
- Git

### Building

```bash
go build -o bin/convert ./cmd/convert
```

### Running manually

```bash
./bin/convert -upstream upstream -output output
```

## Credits

- [Chainguard osquery-defense-kit](https://github.com/chainguard-dev/osquery-defense-kit) - Original query collection
- [0xBEN's approach](https://benheater.com/threat-hunting-fleetdm-osquery/) - Inspiration for FleetDM conversion

## License

The converter tool is MIT licensed. The upstream osquery-defense-kit queries retain their original Apache 2.0 license.
