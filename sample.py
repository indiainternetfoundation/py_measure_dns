from measure_dns import DNSQuery, query_dns4, decode_dns_response

if __name__ == "__main__":
    domain = "ns3.testprotocol.in"
    dns_server = "13.127.175.92"

    result = query_dns4(
        DNSQuery(qname=domain, rdtype="AAAA"),
        dns_server
    )

    if result:
        print(f"\nLatency: {result.latency_ms:.3f} ms")
        print("\nDecoding DNS Response:\n")
        print(result.response.answer)
    else:
        print("Failed to get a response.")
