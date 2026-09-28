# Port Sentinel (port-sentinel)

A high-performance C++ network connection anomaly detector, security triage tool, and log auditor designed for system administrators and security engineers. Inspired by modern host-based intrusion detection systems and Kaite's security toolkit.

## Features

- **Multi-Protocol Telemetry Analysis:** Parses both TCP (`LISTENING`, `ESTABLISHED`, etc.) and UDP (`UNCONN`) connection logs.
- **High-Risk Port Auditing:** Instantly flags activity on known backdoor, malware, and risky ports (e.g., 4444, 1337, 31337, 23, 445).
- **Untrusted Listener Detection:** Detects unexpected listening or unconnected services running on non-standard ports.
- **Structured Outputs:** Supports human-readable terminal reports as well as clean JSON export for SIEM and logging pipelines.
- **Zero External Dependencies:** Built in modern C++17 for maximum portability and speed.
- **Built-in Verification Suite:** Includes a robust self-test mode (`--test`) for continuous validation.

## Building & Installation

Requirements: A C++17 compliant compiler (GCC, Clang, or MSVC).

```bash
g++ -std=c++17 -Wall -Wextra port_sentinel.cpp -o port_sentinel
```

## Usage

Run interactive analysis:
```bash
./port_sentinel
```

Run built-in unit tests:
```bash
./port_sentinel --test
```

Export results as structured JSON:
```bash
./port_sentinel --json
```

## License

MIT License
