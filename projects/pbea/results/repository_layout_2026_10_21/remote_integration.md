# Remote integration checkpoint

Checked 2026-10-21 (Asia/Seoul).

- Original remote main: `61d5f3cd165585934ac78c6fa49ed56f2d7128a7`.
- Verified payload commit on local and remote main: `1f6a52e8e0e121aba6246bd56d4034533b589cfd`.
- All six revision-branch commits, including the user's cleanup, are ancestors of main; the layout and package-verification commits are on main as well.
- The approved remote branch `revision/mdpi-2026-10-20` was deleted using a lease requiring its observed tip `3a0a88e4beace7eaeae58682cdc6d88c375b8f4d`. Its local branch was removed only after integration.
- `git branch -vv` and `git ls-remote --heads origin` then showed only `main`, with local main tracking origin/main and identical payload tips.
- This checkpoint is committed afterwards as audit documentation; that documentation commit advances main without reintroducing a branch.
- Eleven preexisting common Rust-file changes remain only as local CRLF differences. `git diff --ignore-space-at-eol --exit-code` succeeds. They were not committed, discarded or mixed into this layout change.

Remote source updates were explicitly approved by the user. No PR, release, journal submission or external editor message was created. Deleting the merged branch removes only its name; its commits remain reachable through main.
