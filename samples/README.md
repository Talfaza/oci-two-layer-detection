# Samples

Prebuilt image artifacts used by the static detectors. The large binaries are
**git-ignored** to keep the repo lean; they are regenerable.

| Item | Tracked? | What |
|------|:--------:|------|
| `build/` | yes | original build inputs (`Dockerfile.plain`, `payload.sh`, `systemd-journal-cache.sh`) |
| `clean.tar`, `plain.tar`, `stego.tar` | no | `docker save` tarballs of the httpd triplet |
| `stego_oci/` | no | the stego image in OCI layout (~46 MB of blobs) |

## Regenerating

- **Plain image:** `docker build -f samples/build/Dockerfile.plain -t httpd:plain samples/build`
  then `docker save httpd:plain -o samples/plain.tar`.
- **OCI layout from a saved image:**
  `skopeo copy docker-archive:samples/stego.tar oci:samples/stego_oci:stego`.
- **Full end-to-end without any prebuilt data:** `experiments/generalize/run_matrix.sh`
  builds clean/plain/stego variants for real base images from scratch and scans
  them — this is the reproducible path that needs no committed dataset.
