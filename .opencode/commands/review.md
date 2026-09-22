---
description: Review the current changes with the reviewer subagent
agent: reviewer
---

Review this repository's uncommitted changes. If a target or focus is given
below, review that instead.

$ARGUMENTS

Start with `git status --short`, then read the staged and unstaged diffs and any
new untracked files, plus enough surrounding code to judge them in context. Run
`just check` when feasible and report the result. Follow your review checklist,
report findings in severity order with file:line references, then a short
verdict. Do not modify any files.
