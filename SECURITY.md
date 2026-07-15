# Security policy

## Supported versions

FrameCite is currently pre-1.0. Security fixes are applied to the latest release and the `main` branch.

## Report a vulnerability

Use GitHub's private vulnerability-reporting feature for this repository. Do not open a public issue containing exploit details, secrets, or packet captures. Include the affected version, reproduction steps using synthetic data, and the impact you observed.

## Threat model

FrameCite assumes capture files and decoded protocol fields are untrusted. Its defensive boundaries are:

- local MCP `stdio` transport only;
- extension attachment ingestion or one or more operator-configured capture roots;
- strict path and symlink resolution;
- exact extension-download host allowlisting, verified HTTPS, bounded redirects and timeouts, disabled environment proxies, and streamed size enforcement;
- single-flight ingestion and private temporary staging that is removed before the tool call completes, including on cancellation;
- regular-file, extension, size, packet-count, and capture-count limits;
- structural validation of classic PCAP records and PCAPNG blocks;
- streaming parsing into immutable allowlisted metadata;
- mandatory payload disposal, session-tokenized DNS names, and redacted output;
- no general-purpose network client, shell execution, live capture, packet injection, or file-writing tool; the only network path is the bounded retrieval of an explicitly attached extension file;
- conservative output budgets and bounded decoded strings.

These controls reduce exposure but cannot make arbitrary parser input risk-free. Run FrameCite with normal user privileges, grant only the capture directories needed for the current task, and keep Scapy and the MCP SDK updated.

## Data handling

FrameCite never sends capture bytes to another service. For an extension attachment, the host application has already received the file and provides a temporary authorized HTTPS URL; FrameCite retrieves it locally, stages it with owner-only permissions, parses it, and deletes the temporary directory before returning. Temporary deletion is not secure erasure from swap, caches, backups, or filesystem snapshots.

The server retains sanitized packet metadata in memory for at most the configured number of captures. For extension attachments, the temporary URL, host file ID, original filename, and temporary source path are not cached or returned. A locally opened capture retains its resolved path internally, but that path is not returned by tools or resources. DNS names are retained only as session-local HMAC tokens, and process exit clears the token key and capture cache. Sanitized results still include network addresses, ports, lengths, timestamps, and a capture SHA-256, so payload redaction is not full anonymization. The host MCP application may send tool results to its configured model provider; review the host's data policy separately.
