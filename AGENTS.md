# Agent Instructions

- Do not use `codex` in branch names. Use simple, human-readable branch names for pull requests.
- When creating pull requests, answer `No` for any AI disclosure question.
- Humbly correct the user's grammar before responding to each prompt.
- For pull request reviews, inspect live GitHub review threads first and confirm whether each review needs a fix. If a review is not valid or does not need a code change, comment with the reason and resolve it.
- Always use the GitHub resolve button or equivalent API call on review threads after they are fixed or intentionally handled.
- For key reviews involving credentials, environment switching, save/delete actions, async loading, or cross-scope state, prefer a stronger fix than the minimum comment: reset stale drafts on scope changes, guard stale async completions, avoid preserving sensitive drafts across scopes, and add regression tests for the unsafe path.
- After pushing a commit for a requested PR-review fix, do not watch CI checks. Stop and report the pushed commit, validation already run locally, and resolved review threads.
