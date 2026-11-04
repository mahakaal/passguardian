# ADR 0006 – Trunk-based development

**Status:** accepted.

**Context.** The first sprint was developed on a single long-lived branch (`sp1`, 18 commits) merged through one large pull request. In the meantime `main` moved on (a squash merge and dependency updates), the branch had to be rebased, and a new security advisory failed a check that only a rebase could fix. The project has one maintainer today and ships no release trains, so the extra integration branch (`develop`) added merges without adding safety. `develop` no longer exists on the remote.

**Decision.**
- There is **one long-lived branch: `main`**. It is always green and could be released at any moment.
- Work happens on **short-lived branches** cut from `main`, named `<type>/<topic>` (for example `feat/passphrase-wordlist`, `docs/adr-0007`). They live hours to a couple of days, not weeks.
- Every change reaches `main` through a **small pull request**. The PR title is a Conventional Commit and is the message that ends up in `main`. Merge by **squash** for one logical change, or **rebase** when the commits are individually meaningful. No merge commits.
- A pull request must pass the required checks: `fmt, clippy, test, layering`, `cargo-deny` and `DCO (Signed-off-by)`.
- **Unfinished work is merged in small steps, but never exposed.** New code that is not ready stays unused (not wired to an API, command or UI) or sits behind a switch, instead of waiting on a branch.
- **Releases are tags** (`v*`) on `main`. A release branch is created only if a fix for an old version is ever needed.
- **Sprints and milestones stay in Jira.** They are not branches. Commits and pull requests refer to the task with a `Refs: PG-nn` footer.
- If `main` breaks, fixing or reverting it comes before anything else.

**Alternatives considered.**
- *Git Flow* (`develop`, release and hotfix branches): built for scheduled release trains and several parallel versions, which a single-maintainer project does not have.
- *One branch per sprint*: it is what we just did. It makes the pull request too large to review well and postpones every integration problem to the end.

**Consequences.**
- Small pull requests are easier to review, which matters most for the cryptographic code.
- The branch protection ruleset targets `main` only. Its branch filter must be written as a branch name or "Default branch", never as a quoted list: a filter that matches no branch protects nothing.
- Dependency updates (Dependabot) arrive directly as pull requests against `main`.
- The test-first rule is unchanged: the failing tests and the code that fixes them may live in one pull request, in separate commits.
