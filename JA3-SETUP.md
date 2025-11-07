# JA3 Fingerprinting Setup (Optional)

## What is JA3?

JA3 is a method for creating SSL/TLS client fingerprints that are easy to produce and can be easily shared for threat intelligence. It's useful for detecting malware and malicious SSL/TLS clients.

## Why is JA3 disabled by default?

The standard Zeek Docker image (`zeek/zeek:latest`) doesn't include JA3 scripts by default. To keep NetHunt working out-of-the-box, we've disabled JA3 fingerprinting.

## How to enable JA3

### Option 1: Use Zeek with JA3 pre-installed

Use a Docker image that includes JA3:

```bash
# Example with salesforce/ja3
docker pull salesforce/ja3
```

Then update `nethunt/config.py`:
```python
ZEEK_DOCKER_IMAGE = "salesforce/ja3"
```

### Option 2: Install JA3 in native Zeek

If you're using native Zeek installation:

```bash
# Install zkg (Zeek package manager)
sudo apt-get install zeek-aux zeek-zkg

# Install JA3
zkg install ja3

# Verify installation
zeek -N | grep ja3
```

### Option 3: Enable JA3 manually in code

Edit `nethunt/zeek.py` and add back the JA3 script:

**For Docker** (line ~127):
```python
docker_cmd = [
    ...
    "policy/tuning/json-logs.zeek",
    "protocols/ssl/ja3.zeek",  # Add this line
    "frameworks/files/extract-all-files.zeek"
]
```

**For Native** (line ~77):
```python
zcmd = [zeek_bin, "-C", "-r", str(pcap_path),
        "policy/tuning/json-logs.zeek",
        "protocols/ssl/ja3.zeek",  # Add this line
        "frameworks/files/extract-all-files.zeek"]
```

## What you'll get with JA3

When JA3 is enabled, the `ssl.log` file will include:
- `ja3`: JA3 fingerprint hash
- `ja3s`: JA3S (server) fingerprint hash

These can be used to:
- Detect malware families by their SSL/TLS fingerprints
- Identify specific applications
- Track threat actors
- Correlate with threat intelligence feeds

## Testing JA3

After enabling JA3, test with:

```bash
python3 net-hunt.py your_file.pcap -o output/
```

Then check if `ssl.log` contains JA3 hashes:
```bash
jq '.ja3' output/work_1/ssl.log | head -5
```

## References

- JA3 GitHub: https://github.com/salesforce/ja3
- Zeek Package Manager: https://docs.zeek.org/projects/package-manager/
- JA3 on Zeek Packages: https://packages.zeek.org/
