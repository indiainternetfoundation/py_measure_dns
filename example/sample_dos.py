import random

from measure_dns import DNSQuery, send_dns_query, DNSFlags
if __name__ == "__main__":
    N = 1000

    # Define the domain to be queried
    qname_type_list = [
        ("ns1.testprotocol.in", "A"),
        ("ns1.testprotocol.in", "AAAA"),
        ("ns2.testprotocol.in", "A"),
        ("ns2.testprotocol.in", "AAAA"),
        ("ns3.testprotocol.in", "A"),
        ("ns3.testprotocol.in", "AAAA"),
        ("ns4.testprotocol.in", "A"),
        ("ns4.testprotocol.in", "AAAA"),
        ("testprotocol.in", "A"),
        ("testprotocol.in", "NS"),
        ("testprotocol.in", "AAAA"),
    ]

    qname_rdata_choices = random.choices(qname_type_list, k=N)

    # Define the DNS server to query (IPv6 addresses of authoritative nameservers)
    # dns_server = "2406:da1a:8e8:e863:ab7a:cb7e:2cf9:dc78"  # ns1.testprotocol.in
    # Other available nameservers (commented out)
    # dns_server = "2406:da1a:8e8:e8cb:97fe:3833:8668:54ad" # ns2.testprotocol.in
    # dns_server = "2406:da18:c78:2b8:a93c:708c:4fc7:f75d" # ns3.testprotocol.in
    dns_server = "13.127.175.92"  # ns4.testprotocol.in
    # dns_server = "65.0.92.216" # ns2.testprotocol.in (IPv4)
    # dns_server = "13.127.175.92" # ns1.testprotocol.in (IPv4)
    query_list = []

    for i in range(N):
        qname, rdata = qname_rdata_choices[i]
        query_list.append(DNSQuery(qname=qname, rdtype=rdata))

    while True:
        # Send a DNS query to the specified server, requesting an A record
        result = send_dns_query(
            random.choice(query_list),
            dns_server,
            # DNSFlags.PdmMetric  # Requesting PDM (Performance Diagnostic Metrics) option
        )

        # Check if a response was received
        if result:
            print(f"Latency: {result.latency_ns} ns")  # Print query response latency
            print(result.response.answer)  # Print DNS response
        else:
            print("Failed to get a response.")  # Indicate query failure
