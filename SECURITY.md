# Security policy

## Supported versions

FrameCite is currently pre-1.0. Security fixes are applied to the latest release and the `main` branch.

## Report a vulnerability

Use GitHub's private vulnerability-reporting feature for this repository. Do not open a public issue containing exploit details, secrets, or packet captures. Include the affected version, reproduction steps using synthetic data, and the impact you observed.

## Threat model

FrameCite assumes capture files and decoded protocol fields are untrusted. Its defensive boundaries are:

- local MCP `stdio` transport only;
- one or more operator-configured capture roots;
- strict path and symlink resolution;
- regular-file, extension, size, packet-count, and capture-count limits;
- streaming parsing into immutable allowlisted metadata;
- mandatory payload disposal and redacted output;
- no runtime network client, shell execution, live capture, packet injection, or file-writing tool;
- conservative output budgets and bounded decoded strings.

These controls reduce exposure but cannot make arbitrary parser input risk-free. Run FrameCite with normal user privileges, grant only the capture directories needed for the current task, and keep Scapy and the MCP SDK updated.

## Data handling

Capture bytes never leave the local process through FrameCite. The server retains sanitized packet metadata in memory for at most the configured number of captures. Process exit clears that cache. The host MCP application may still send tool results to its configured model provider; review the host's data policy separately.
