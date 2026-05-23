---
name: pr-workflow
description: Create pull requests for esphome/aioesphomeapi. Use when creating PRs, submitting changes, or preparing contributions.
allowed-tools: Read, Bash, Glob, Grep
---

# aioesphomeapi PR Workflow

When creating a pull request for `esphome/aioesphomeapi`, follow
these steps. Repo-wide conventions live in
[CLAUDE.md](../../../CLAUDE.md); this skill summarises the parts
that matter at PR-creation time.

## 1. Create branch from origin/main

There is no fork in this workflow — `origin` already points at
`esphome/aioesphomeapi`. Always re-fetch first so the branch is
based on the latest `main`:

```bash
git fetch origin
git checkout -b <branch-name> origin/main
```

## 2. Read the PR template

Before creating a PR, read `.github/PULL_REQUEST_TEMPLATE.md` and
fill in **every** section. The template asks for:

- **What does this implement/fix?** — prose description.
- **Types of changes** — tick exactly one of: `Bugfix`,
  `New feature`, `Breaking change`,
  `Code quality improvements to existing code or addition of tests`,
  or `Other`. Pick the one a future release-notes reader would
  expect; release-drafter slots PRs by label
  (`breaking-change`, `new-feature`, `bugfix`, `enhancement`,
  `documentation`, `dependencies`).
- **Related issue or feature** — `fixes <link>` syntax if
  applicable.
- **Pull request in esphome** — link the companion PR if the
  change requires firmware-side work; mandatory if `api.proto`
  is modified (see step 3).
- **Checklist** — only tick boxes you've actually verified.

## 3. api.proto changes need an upstream PR first

The protocol is defined firmware-side. If the PR modifies
`aioesphomeapi/api.proto`, the matching change MUST land in
`esphome/esphome` first; link the esphome PR in the body and tick
the "linked pull request has been made to esphome" checkbox. After
modifying the proto, regenerate the bindings with the docker image
documented in [CLAUDE.md](../../../CLAUDE.md#regenerating-protobuf-files)
so `api_pb2.py` stays in sync with the protobuf runtime version.

## 4. Commit message conventions

- **Imperative-mood subject line** — "Add X", not "Added X".
- **No `Co-Authored-By: Claude` trailer.** Project preference.
- One logical change per commit; let pre-commit run (ruff lint +
  format). If a hook auto-fixes something, re-stage and re-commit.

## 5. Push and create the PR

**Read `.github/PULL_REQUEST_TEMPLATE.md` from the repo at
PR-creation time and use it verbatim as the body** — do not
reproduce, paraphrase, or trim the template anywhere else, or it
will silently drift out of sync as the template evolves.

When filling in the template:

- Replace the `<!-- ... -->` prompt comments with the actual prose
  for that section. Do not delete anything else.
- **Leave all the checkboxes in place.** Do not remove rows you
  aren't ticking — the auto-labeller and the human reviewer both
  rely on the full list being present.
- Tick exactly one "Types of changes" box. For the Checklist
  section, only tick boxes you have actually verified; leave the
  rest as `- [ ]`.
- **Do not escape characters from the template.** Backticks,
  asterisks, angle brackets, etc. must be passed through verbatim.
  The template is already valid Markdown; do not rewrite it for
  shell quoting. Use `--body-file`, never `--body "..."` with
  shell-escaping.

```bash
git push -u origin <branch-name>
# Read .github/PULL_REQUEST_TEMPLATE.md, fill it in as above,
# write the result to a temp file, then:
gh pr create --repo esphome/aioesphomeapi --base main \
  --title "Imperative subject under 70 chars" \
  --body-file /tmp/pr-body.md
```

The keep-the-checklist-honest rule applies — only tick a checklist
box you've actually verified. "Tests have been added" is verified
by pointing at the new test file in the diff; "linked PR to
esphome" is verified by clicking the link.

## 6. After the PR is open

CI runs ruff (lint + format), the test matrix, and the file-glob
labeller (`.github/workflows/labeler.yml` only auto-labels
`dependencies` based on changed files; the other release-drafter
labels — `bugfix`, `new-feature`, `breaking-change`,
`enhancement`, `documentation` — are applied by maintainers from
the Types-of-changes tick). If a maintainer relabels, that's not
a sign your tick was wrong — it's the editorial slotting for the
release notes.
