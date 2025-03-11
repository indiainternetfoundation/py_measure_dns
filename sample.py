from measure_dns import DNSQuery, send_dns_query, DNSFlags

if __name__ == "__main__":
    domain = "testprotocol.in"
    dns_server_ipv6 = "2406:da1a:8e8:e8cb:97fe:3833:8668:54ad" # NS2

    result_v6 = send_dns_query(
        DNSQuery(qname=domain, rdtype="A"),
        dns_server_ipv6,
        DNSFlags.PdmMetric
    )

    if result_v6:
        print(f"\nLatency: {result_v6.latency_ms} ms")
        print("\nDecoding DNS Response:\n")
        print(result_v6.response.answer)
    else:
        print("Failed to get a response v6.")

