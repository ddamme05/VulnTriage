# VulnTriage

**Democratizing reachability analysis for vulnerability triage.**

VulnTriage bridges the gap between "Vulnerable Package" and "Exploitable Code," turning a list of 500 scanner alerts into a list of 5 actionable tasks.

## Quick Start

### Prerequisites
- Python 3.12+
- [uv](https://github.com/astral-sh/uv) installed
- [Trivy](https://trivy.dev/) installed
- OpenAI API Key

### Install
```bash
git clone https://github.com/yourusername/vuln-triage.git
cd vuln-triage
uv sync
```

### Usage
```bash
# Generate Trivy report
trivy fs . --format json --output trivy.json

# Run triage
export OPENAI_API_KEY="sk-..."
uv run vulntriage scan --trivy-json trivy.json --src .
```

## Architecture

| Component | Tech | Role |
|-----------|------|------|
| Scanner | Trivy | Finds CVEs in dependencies |
| Parser | Tree-sitter | Finds imports and call sites |
| Engine | Python + Pydantic | Orchestrates analysis |
| Analyst | GPT-4o | Reasons about exploitability |
| UI | Typer + Rich | CLI experience |

## Documentation

See [docs/README.md](docs/README.md) for the full deep dive.

## License

MIT
