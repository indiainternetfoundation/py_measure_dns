# Architecture: DNS Measurement Tool

This project sends raw DNS queries and measures latency, optionally capturing diagnostic metrics like PDM. It combines Python for query construction and response parsing with C for low-level network operations.

---

## Components

| File | Responsibility |
|------|----------------|
| `measuredns.c` | C code that sends DNS packets, measures latency, and adds PDM if enabled |
| `c_interface.py` | Connects Python with the C code using `ctypes` |
| `dns_packet.py` | Builds DNS query packets using `dnspython` |
| `measure_dns.py` | Main logic to send queries and process results |

---

## Data Flow

1. `measure_dns.py` defines a `DNSQuery` and calls `send_dns_query(...)`
2. `dns_packet.py` builds the raw DNS packet (wire format)
3. `c_interface.py` loads `measuredns.so` and sends the packet using `query_dns(...)`
4. `measuredns.c` sends the query over a socket, optionally adds PDM, and measures latency
5. Response and optional diagnostics are returned to Python
6. The response is parsed and returned as a `DNSResult`

---

### Flow Diagram

```text
[ measure_dns.py ]
        │
        ▼
[ dns_packet.py ] → Builds DNS packet
        │
        ▼
[ c_interface.py ] → Sends to C library
        │
        ▼
[ measuredns.c ] → Sends packet, measures latency, adds PDM
        │
        ▼
[ DNSResult ] ← Raw response and metrics returned
```

## Supported Features
IPv4 & IPv6 DNS queries

PDM (Performance Diagnostic Metrics)

Precise Latency measurements

## How To Run
1. The `sample.py` file can be used to Query the DNS Server hose ip address is specified in the query.
2. This file executes the `send_dns_query` function the sned the query.
3. We can also run the `sample_dos` file to send a bunch of queries at a time to the same dns server.  
```bash
   $python3 -m sample.py
   $python3 -m sample_dos.py
```
## Expected Output
1. By running the `sample.py` file the user should be able to see the following output.
```bash
    Latency: 32746846.0 ns
    [<DNS ns4.testprotocol.in. IN A RRset: [<18.141.183.65>]>]
    Latency: 30242277.0 ns
    [<DNS testprotocol.in. IN NS RRset: [<ns4.testprotocol.in.>, <ns1.testprotocol.in.>, <ns3.testprotocol.in.>, <ns2.testprotocol.in.>]>]
    Latency: 25007498.0 ns
```
