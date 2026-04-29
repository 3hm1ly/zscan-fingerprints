# zscan-fingerprints

Auto-syncing mirror for the zscan platform's fingerprint pipeline.

## What this repo does

GitHub Actions workflows pull from upstream and republish artifacts so
zscan workers running inside Tencent Cloud (where direct GitHub access
times out) can fetch them via CDN mirrors.

| workflow | upstream | output |
|---|---|---|
| `mirror-spray-release.yml` | [`chainreactors/spray`](https://github.com/chainreactors/spray) | latest spray binary republished as our release |
| `sync-fingerprints.yml` | [`0x727/FingerprintHub`](https://github.com/0x727/FingerprintHub) | `web_fingerprint_v4.json` converted to fingers YAML format, published as a dated release |

Both workflows run on a daily/weekly schedule and on-demand via `workflow_dispatch`.

## How worker fetches artifacts

JSDelivr CDN is the primary route (works inside Tencent Cloud most of the time):

```
https://cdn.jsdelivr.net/gh/3hm1ly/zscan-fingerprints@latest/<asset>
```

Worker-side `sync_fingerprints.sh` walks a fallback chain
(JSDelivr → ghproxy → direct GitHub → cached local copy).
See `apps/worker/deploy/sync_fingerprints.sh` in the main zscan repo.

## Manual trigger

Both workflows expose `workflow_dispatch`:

```bash
gh workflow run mirror-spray-release.yml --repo 3hm1ly/zscan-fingerprints
gh workflow run sync-fingerprints.yml    --repo 3hm1ly/zscan-fingerprints
```

## Schedule

| workflow | cron | rationale |
|---|---|---|
| mirror-spray-release | `0 4 * * *` (daily 04:00 UTC) | spray releases ~monthly; daily check is cheap |
| sync-fingerprints | `0 4 * * 1` (Monday 04:00 UTC) | FingerprintHub updates daily upstream; weekly sync is plenty for production |

## Layout

```
.github/workflows/
  mirror-spray-release.yml
  sync-fingerprints.yml
scripts/
  fph_to_fingers.py          # FingerprintHub JSON → fingers YAML converter
README.md
```
