# Verify

Since `sesam` is a tool focused on security. We need to constantly check whether we have been compromised
and warn the user therefore. There are several checks that are being run, which will be explained in this chapter.

```admonish warning
We recommend running `sesam verify --all` as part of your CI/CD pipeline.
```

## Audit Log

The audit log is a list of entries, each describing a change to the repository.
You can view it in `.sesam/audit/log.jsonl`. Each entry is linked to the previous one
via a hash and protected by a signature of the user that made the change.

Additionally, we store the hash of the first entry and check if it was modified
over git history as trust anchor. This makes truncating the log harder.

On almost every `sesam` command we will verify the integrity of the log. Failure to do so
is fatal and requires investigation on why the state could not be verified.

## Audit Log truncate

Check commit tree to see if the audit log in the commit before was a prefix of the current one.
The log is completely linear, so this catches malicious truncation events.

This will be run on `sesam verify --trunc`

## File integrity

The `age` encryption format does not by default provide integrity. One could still try to replace it with another file.
Luckily, `sesam` writes a signature and hash for each file and thus allows catching deviations from the expected state.

This will be run on `sesam verify --fsck`

Automatically run on `sesam reveal --pull`.

## Forge checks

When using forge user IDs like `github:sahib` we can check whether they match with the locally cached public key.
This is not a security issue per se, but it can mean that a user might have locked himself out because he might have removed his old key.

This will be run on `sesam verify --forge`
