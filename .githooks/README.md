# Repo hooks

One-time setup per clone (both lines — git does not read either from the repo):

```sh
git config core.hooksPath .githooks
git config blame.ignoreRevsFile .git-blame-ignore-revs
```

## What they do

`pre-commit` refuses a commit that contains an unformatted Go file. This exists
because commit `a08e682` mixed a `gofmt` sweep of 120 files into a 2-file logic
change, which made `git blame` across `pkg/execution` useless. That commit has
since been split into `b51868a` (formatting only) and `e4ace29` (the logic).

Format the whole main module with:

```sh
sh .githooks/gofmt-check.sh --fix
```

Formatting fixes go in their own commit, never mixed with logic, and the hash
gets added to `.git-blame-ignore-revs`.

The vendored `accumulate-lite-client-2/liteclient` module is excluded from all
of this on purpose — it tracks upstream, and reformatting it would make future
upstream comparisons unreadable.
