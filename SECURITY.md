# Security policy

scopedmail limits what an AI agent can do with a mailbox. A bug that lets an agent get past the policy, the `files_dir` limit, or the audit log is a security issue. So is a bug that lets the agent reach the credentials.

## Report a vulnerability

Report it privately through GitHub's private vulnerability reporting:

1. Open the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Describe the issue. Include the scopedmail commit, the config with its secrets removed, the commands you ran, and what happened.

Do not open a public issue or pull request for a vulnerability before it is fixed.

## What to expect

You get a reply in the advisory thread. When the issue is confirmed, the fix and a GitHub security advisory are published together. The advisory credits you unless you ask not to be named.

## Supported versions

scopedmail has no stable release yet. Fixes land on the `main` branch only.

## In scope

- An action the policy denies that still reaches the server.
- An action that changes mail or sends it with no record in the audit log.
- A path outside `files_dir` that scopedmail reads or writes for the agent.
- An agent that runs a program of its choice as the service user, or reads the config or credentials, in the separate-user setup that the README describes.

An agent that runs as the same OS user as scopedmail is out of scope. The README's threat model explains why.
