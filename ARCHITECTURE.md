# NetHunt Architecture

## Overview

NetHunt è stato refactorato in una struttura modulare per migliorare la manutenibilità, testabilità e organizzazione del codice.

## Structure

```
NetHunt/
├── net-hunt.py              # CLI entry point (refactored)
├── nethunt/                 # Main package
│   ├── __init__.py         # Package initialization
│   ├── config.py           # Configuration constants
│   ├── utils.py            # Utility functions
│   ├── zeek.py             # Zeek execution (Docker & native)
│   ├── suricata.py         # Suricata configuration & execution
│   ├── tshark.py           # Tshark file extraction
│   ├── parsers.py          # Log parsing (HTTP, DNS, SSL)
│   ├── beaconing.py        # Beaconing detection algorithm
│   ├── report.py           # HTML/JSON report generation
│   └── analyzer.py         # Main analysis orchestration
├── test_*.py               # Unit tests
├── install-tools.sh        # Installation script
└── README.md               # User documentation
```

## Module Responsibilities

### `config.py`
- Global configuration constants
- Zeek Docker image name
- Beaconing detection thresholds
- Tool paths and settings

### `utils.py`
- Binary detection (`check_bin`)
- File system operations (`safe_mkdir`, `ensure_file_readable`)
- Format helpers (`format_bytes`)
- Executable validation (`is_executable`)

### `zeek.py`
- Docker availability checks
- Zeek Docker image management
- Native Zeek binary resolution
- Zeek execution (both Docker and native modes)

### `suricata.py`
- YAML configuration generation
- Suricata execution with EVE logging
- File extraction via Suricata filestore

### `tshark.py`
- Object extraction from PCAP
- HTTP, FTP, SMB protocol object export

### `parsers.py`
- Zeek log parsing (JSON format)
- HTTP traffic analysis (URLs, methods, hosts, user-agents)
- DNS query extraction
- TLS/SSL connection analysis (JA3 fingerprints, server names)
- File deduplication by SHA256

### `beaconing.py`
- Statistical analysis of connection patterns
- Coefficient of variation calculation
- Beacon scoring algorithm
- C2 detection logic

### `report.py`
- Modern HTML report generation
- Responsive CSS styling
- Data visualization tables
- Statistics dashboard

### `analyzer.py`
- Main orchestration logic
- Tool coordination (Zeek, Suricata, Tshark)
- Data aggregation from multiple sources
- Report generation pipeline
- Clean console output formatting

## Design Principles

1. **Separation of Concerns**: Each module has a single, well-defined responsibility
2. **Modularity**: Easy to add new features or swap implementations
3. **Testability**: Each module can be tested independently
4. **Clean Output**: User-friendly console messages with progress indicators
5. **Error Handling**: Graceful degradation when tools are unavailable

## Execution Flow

```
net-hunt.py (CLI)
    ↓
analyzer.analyze()
    ├── Tool detection (Zeek, Suricata, Tshark)
    ├── PCAP chunking (optional)
    └── For each PCAP chunk:
        ├── zeek.run_zeek_docker() or zeek.run_zeek_native()
        ├── suricata.run_suricata()
        ├── tshark.export_objects()
        ├── Parse logs:
        │   ├── parsers.parse_http_log()
        │   ├── parsers.parse_dns_log()
        │   └── parsers.parse_ssl_log()
        └── Collect extracted files
    ├── beaconing.detect_beacons()
    ├── parsers.deduplicate_files()
    ├── Aggregate results
    ├── report.generate_html_report()
    └── Save JSON and HTML reports
```

## Benefits of This Architecture

### Maintainability
- Easy to locate and fix bugs
- Clear module boundaries
- Self-documenting code structure

### Extensibility
- Add new tools by creating new modules
- Easy to add new report formats
- Simple to extend parsing capabilities

### Testing
- Each module can be unit tested independently
- Mock dependencies easily
- Test coverage is more comprehensive

### Performance
- Modules can be optimized independently
- Easy to parallelize operations
- Clear bottleneck identification

## Migration Notes

The old monolithic `net-hunt.py` has been backed up as `net-hunt-old.py`. The new version:
- Uses the same CLI interface (backward compatible)
- Produces identical output
- Has cleaner, more intuitive console messages
- Is easier to maintain and extend

## Future Improvements

Potential enhancements:
1. Plugin system for custom analyzers
2. Parallel processing for large PCAPs
3. Real-time analysis mode
4. Machine learning-based anomaly detection
5. Integration with threat intelligence feeds
