# scripts/

Helper scripts for local dev. Not used in production.

| Script | What it does |
|---|---|
| `setup-local-backstage.ps1` (Windows) / `setup-local-backstage.sh` (mac/linux) | One-time setup that scaffolds a Backstage app under `local-backstage/`, applies our overlay config, and builds a Docker image so the Aspire AppHost can launch it via `--with-backstage`. See [`docs/operations/local-backstage.md`](../docs/operations/local-backstage.md). |

Run them from the repo root:

```powershell
# Windows
./scripts/setup-local-backstage.ps1
```

```bash
# mac / linux
./scripts/setup-local-backstage.sh
```
