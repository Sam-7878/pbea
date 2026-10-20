# PBEA base research project

This directory holds resources shared by the PBEA project's milestones. Repository-wide reusable code remains in `crates/` and `protocol/`; do not maintain a second framework copy here.

- `evaluation/mdpi_revision/`: PBEA revision validation, table generation and packaging tools.
- `paper/mdpi_revision/`: current MDPI working draft sources. `paper/references.bib` is the unchanged bibliography snapshot copied from the preserved original manuscript; the working draft reads this project-wide copy.
- `resources/`: reserved for future PBEA-wide resources, not individual task results.
- `results/204_Astra_review/`: moved revision evidence, reports, rendered pictures, PDFs, logs and archives.
- `results/repository_layout_2026_10_21/`: branch-integration and byte-preserving migration audit.

The [204 reproduction guide](results/204_Astra_review/REPRODUCTION.md) contains current commands. Original 2026-10-20 archives/manifests are retained unchanged; a migrated-layout package and manifest have a separate `layout_2026_10_21/` subdirectory. Neither local packaging nor a source push publishes a journal submission or a public DOI.

New milestone data belong in `results/<task>/`. Project-wide documentation/resources go outside `results/`; task-only reports and pictures go inside that task's result directory.
