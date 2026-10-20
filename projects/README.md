# Shared repository and project layout

The repository at `/mnt/d/_Work/goat_bank/pbea` is managed on `main`. PBEA is the base project; `open_banking` and `swarm_drones` are planned derivatives. Project separation is by directories, not by long-lived project branches.

```text
pbea/                               repository root: shared framework
  crates/                           shared Rust libraries and existing examples
  protocol/                         shared protocol and policy definitions
  evaluation/                       existing reusable/historical comparative tools
  docs/                             shared documentation and retained legacy archives
  projects/
    pbea/
      README.md                     PBEA-wide navigation
      evaluation/mdpi_revision/     tools reused across PBEA milestones
      paper/                        PBEA manuscript sources and shared bibliography
      resources/                    future cross-milestone pictures/fixtures/resources
      results/
        204_Astra_review/           retained MDPI revision task outputs
        repository_layout_2026_10_21/  repository integration/migration audit
    open_banking/
      README.md
      results/<task>/               future task-specific outputs
    swarm_drones/
      README.md
      results/<task>/               future task-specific outputs
```

## Placement rules

- Put code/specifications actually shared between projects at the repository root's appropriate existing location. Do not copy/fork the shared crates into each project.
- Put project-only material reused by several milestones in `projects/<project>/evaluation/`, `paper/`, `docs/` or `resources/`, as appropriate.
- Store each task's raw data, derived metrics, reports, pictures, PDFs and logs together under `projects/<project>/results/<task>/`. Use a unique task identifier; do not overwrite a completed task with a later campaign.
- Do not put project/task artifacts directly at the repository root or in a project-wide resource folder merely because they were generated there.
- Keep secrets in the existing ignored `local_security/` (or another explicitly ignored private location), never in tracked project resources or reviewer packages. Real customer data must not be added automatically.
- Keep `main` as the integration branch. Temporary branches, if explicitly needed later, are integrated and removed after verification. This layout does not require a branch per project or per milestone.

This migration relocates the 204 revision, its dedicated analysis tools and the revised manuscript. Earlier reports and original manuscripts remain in their historical `docs/` locations to preserve provenance; this is not an unreviewed wholesale migration of every old document. Existing paths inside archived logs/manifests remain historical facts, not active output destinations.
