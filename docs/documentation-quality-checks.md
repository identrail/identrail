# Documentation Quality Checks

Use this checklist before merging documentation changes.

## Required Checks

1. Local links resolve correctly.
2. New docs are indexed in `docs/README.md`.
3. API behavior statements match current handlers/contracts.
4. Env var references match `internal/config/config.go` and `internal/config/security.go`.
5. Web routes stay synchronized across router, prerender list, and sitemap.

## Link Integrity Check (local)

Run from repo root:

```bash
python3 - <<'PY'
import re
from pathlib import Path
root=Path('.').resolve()
paths=[root/'docs', root/'deploy', root/'site', root/'README.md']
files=[]
for p in paths:
    if p.is_file():
        files.append(p)
    elif p.is_dir():
        files.extend(x for x in p.rglob('*.md') if 'node_modules' not in x.parts and '.next' not in x.parts)
errors=[]
for f in files:
    txt=f.read_text(errors='ignore')
    for m in re.finditer(r'\[[^\]]+\]\(([^)]+)\)', txt):
        raw=m.group(1).strip()
        path=raw[1:].split('>', 1)[0] if raw.startswith('<') else raw.split(None, 1)[0]
        t=path.split('#',1)[0]
        if not t or t.startswith(('http://','https://','mailto:','#')):
            continue
        if not (f.parent/t).resolve().exists():
            errors.append((f,t))
if errors:
    for f,t in errors:
        print(f"{f}: {t}")
    raise SystemExit(1)
print('OK: no broken local markdown links')
PY
```

## Web Route Integrity Check

Before merge, verify manually (or via CI guard when enabled) that:

1. Static routes in `web/src/App.tsx` are included in `web/prerender-routes.ts`.
2. Prerender routes are included in `web/public/sitemap.xml`.

## Route Change Rules

When adding a real, live page:

1. Add the route in `web/src/App.tsx`.
2. Add the route to `PRERENDER_ROUTES` in `web/prerender-routes.ts`.
3. Add the route URL in `web/public/sitemap.xml`.

When a page is planned but not implemented yet:

1. Do not add speculative route URLs to sitemap/prerender lists.
2. Keep references as explicit TODO notes in docs/config until the page exists.
