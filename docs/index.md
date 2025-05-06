
# Welcome to measure_dns

`measure_dns` is a Python package designed for precise measurement of DNS query times. Unlike traditional Python-based DNS measurement tools, which suffer from timing inaccuracies due to high-level language overhead, `measure_dns` leverages a C-based core for improved accuracy. It also supports Performance Diagnostic Metrics (PDM) to extract detailed latency breakdowns, making it useful for network performance analysis.

---

## Key Features
- **Accurate Timing:** Uses a C core to provide precise latency measurements.
- **DNS Query Support:** Supports querying various record types (e.g., A, AAAA, MX, etc.).
- **Performance Diagnostic Metrics (PDM):** Extracts network and server processing latency.
- **IPv4 & IPv6 Support:** Query DNS servers over both IPv4 and IPv6 networks.

## Getting Started
To get started with `measure_dns`, you need Python 3.x and basic understanding of DNS querying. `measure_dns` requires `gcc` to compile the C components. Ensure you have `gcc` installed before proceeding.

### Install Toolchain

This package depends on some toolchains like gcc to build binaries.

=== "Debian/Ubuntu"
    To install the required toolchain like gcc for debian based systems, 

    ```bash
    $ sudo apt update && sudo apt install gcc -y
    ```

=== "Windows"
    Coming Soon ...

=== "MacOS"
    To install the required toolchain like gcc for macOS(via Homebrew) based systems, 

    ```bash
    $ brew install gcc
    ```

### Install measure_dns

Currently, `measure_dns` is not available on PyPI and must be installed from GitHub:
```bash
$ pip install git+https://github.com/indiainternetfoundation/py_measure_dns
```

## A Quick Start

### Example: Measuring DNS Query Time

```py
from measure_dns import DNSQuery, send_dns_query, DNSFlags

# Define the domain to be queried
qname = "testprotocol.in"

# Define the DNS server to query (IPv4 / IPv6 address of an authoritative nameserver)
dns_server = "2406:da1a:8e8:e863:ab7a:cb7e:2cf9:dc78"

# DNS Query in dnspython format
query = DNSQuery(qname=qname, rdtype="A")

# Send a DNS query to the specified server, requesting an A record
result = send_dns_query(
    query,
    dns_server,
)

# Check if a response was received
if result:
    print(f"Latency: {result.latency_ns} ns")
    print(result.response.answer)
else:
    print("Failed to get a response.")
```

### How It Works
1. The `DNSQuery` class constructs a query for a given domain and record type.
2. The `send_dns_query` function sends the query to a specified DNS server and measures the response time.
3. The `PDM` option, if enabled, provides additional performance metrics.
```py
# Send a DNS query to the specified server, requesting an A record
result = send_dns_query(
    qname,
    dns_server,
    DNSFlags.PdmMetric  # Requesting PDM (Performance Diagnostic Metrics) option
)
```
4. The result includes the response data along with precise latency information.


## Documentation
Detailed documentation is available for the core components of `measure_dns`:

- [API Reference](api.md)
- [Examples](examples/index.md)

## Contribution Guide
Please see our [Contributing Guide](contributing.md) for more information on how you can contribute to the project.

## License
This project is licensed under the GNU General Public License - see the [LICENSE](license.md) file for details.
