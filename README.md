# NetProbe

NetProbe is a lightweight Python-based network reconnaissance tool for authorized security learning and basic host assessment. It identifies open TCP ports, detects likely services, optionally grabs simple banners, and provides heuristic OS fingerprinting from TTL and service hints.

NetProbe is designed to explain the shape of a scanning pipeline. It is not meant to replace mature scanners such as Nmap.

## Features

- TCP connect scanning for single hosts
- Configurable port ranges and comma-separated port lists
- Thread pool based concurrent scanning
- Optional banner grabbing for common service types
- Heuristic OS fingerprinting from ping TTL and open service hints
- Clean terminal output with optional Rich tables
- Text, JSON, and CSV output based on file extension

## Project Structure

```text
NetProbe/
├── main.py
├── scanner.py
├── banner_grabber.py
├── os_fingerprint.py
├── output.py
├── utils.py
├── requirements.txt
└── README.md
```

## Installation

```bash
cd NetProbe
python -m venv venv
```

Windows:

```bash
venv\Scripts\activate
```

Linux/macOS:

```bash
source venv/bin/activate
```

Install optional display dependencies:

```bash
pip install -r requirements.txt
```

The scanner still runs without these dependencies, but the banner and table output will be simpler.

## Usage

Scan common ports:

```bash
python main.py -t 192.168.1.1
```

Scan a custom port range:

```bash
python main.py -t 192.168.1.1 -p 1-1024
```

Scan selected ports:

```bash
python main.py -t 192.168.1.1 -p 22,80,443,8080
```

Enable banner grabbing:

```bash
python main.py -t 192.168.1.1 --banner
```

Enable OS fingerprinting:

```bash
python main.py -t 192.168.1.1 --os
```

Save JSON output:

```bash
python main.py -t 192.168.1.1 -p 1-1024 --banner --os -o scan.json
```

Save CSV output:

```bash
python main.py -t 192.168.1.1 -p 1-1024 -o scan.csv
```

## CLI Arguments

| Argument | Description |
| --- | --- |
| `-t`, `--target` | Target IP address or hostname |
| `-p`, `--ports` | Port range or list, such as `1-1024` or `22,80,443` |
| `--banner` | Enable banner grabbing |
| `--os` | Enable OS fingerprinting |
| `-o`, `--output` | Save results to `.txt`, `.json`, or `.csv` |
| `--timeout` | Connection timeout in seconds |
| `--threads` | Maximum concurrent scan workers |
| `--show-closed` | Show closed and filtered ports in terminal output |

## Development Roadmap

- Phase 1: Single-port TCP connect scanner
- Phase 2: Multi-port scanning
- Phase 3: Multi-threaded execution
- Phase 4: Banner grabbing
- Phase 5: OS fingerprinting
- Phase 6: Structured output formats

## Tech Stack

- Python
- Socket programming
- ThreadPoolExecutor
- JSON and CSV
- Rich
- PyFiglet

## Future Enhancements

- CIDR range scanning
- Service fingerprint database
- Host discovery
- UDP scanning
- Advanced OS fingerprinting
- Scan progress indicators

## Disclaimer

This tool is intended for educational purposes and authorized security assessments only. Users are responsible for ensuring compliance with all applicable laws and regulations.
