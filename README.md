# Lazarus working repository (experiment build)

This repository holds one revival job for one open source project. The project's source is committed
to a `subject-<job>` branch as a snapshot, with its own workflows removed. The only workflow is
`.github/workflows/lazarus.yml`. Results are written to the `lazarus-result` branch under `results/<job>/`.
