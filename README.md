# py_measure_dns

`measure_dns` is a Python package designed for precise measurement of DNS query times. Unlike traditional Python-based DNS measurement tools, which suffer from timing inaccuracies due to high-level language overhead, `measure_dns` leverages a C-based core for improved accuracy. It also supports Performance Diagnostic Metrics (PDM) to extract detailed latency breakdowns, making it useful for network performance analysis.

---

## Features
- **Accurate Timing:** Uses a C core to provide precise latency measurements.
- **DNS Query Support:** Supports querying various record types (e.g., A, AAAA, MX, etc.).
- **Performance Diagnostic Metrics (PDM):** Extracts network and server processing latency.
- **IPv4 & IPv6 Support:** Query DNS servers over both IPv4 and IPv6 networks.

---

## Installation

Currently, `measure_dns` is not available on PyPI and must be installed from GitHub:
```bash
$ pip install git+https://github.com/arnavdas88/py_measure_dns
```

---

## Usage

### Example: Measuring DNS Query Time

```python
import socket
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

---

## How It Works
1. The `DNSQuery` class constructs a query for a given domain and record type.
2. The `send_dns_query` function sends the query to a specified DNS server and measures the response time.
3. The `PDM` option, if enabled, provides additional performance metrics.

```python
# Send a DNS query to the specified server, requesting an A record
result = send_dns_query(
    qname,
    dns_server,
    DNSFlags.PdmMetric  # Requesting PDM (Performance Diagnostic Metrics) option
)
```

4. The result includes the response data along with precise latency information.

---

## Supported Record Types
The package supports querying standard DNS record types, including:
- **A (IPv4 Address)**
- **AAAA (IPv6 Address)**
- **CNAME (Canonical Name)**
- **MX (Mail Exchange)**
- **TXT (Text Record)**
- **NS (Name Server)**

---

## License
`measure_dns` is released under the MIT License.

---

## Contribution
Contributions are welcome! Feel free to open issues or submit pull requests on [GitHub](https://github.com/arnavdas88/py_measure_dns).

