import socket
import dns

from measure_dns import DNSQuery, send_dns_query, DNSFlags

# Function to convert delta time values to nanoseconds based on scale factor
def _astons(delta, scale):
    ns_time = delta
    ns_time = int(ns_time) << (scale - 8)  # Adjust the time based on the scale factor
    ns_time *= 16 * 16  # Further conversion to align with PDM metric format
    ns_time /= 10000
    ns_time /= 100000
    return int(ns_time)


if __name__ == "__main__":
    # Define the domain to be queried
    domain = "cloudflare.in"

    # Define the DNS server to query (IPv6 addresses of authoritative nameservers)
    # dns_server = "13.127.175.92"  # ns1.testprotocol.in
    # Other available nameservers (commented out)
    dns_server = "2406:da1a:8e8:e8cb:97fe:3833:8668:54ad" # ns2.testprotocol.in
    # dns_server = "2406:da18:c78:2b8:a93c:708c:4fc7:f75d" # ns3.testprotocol.in
    # dns_server = "2406:da18:c78:219:22a5:8271:5f0d:780b" # ns4.testprotocol.in
    # dns_server = "65.0.92.216" # ns2.testprotocol.in (IPv4)
    # dns_server = "8.8.8.8" # ns1.testprotocol.in (IPv4)

    # Send a DNS query to the specified server, requesting an A record
    result = send_dns_query(
        DNSQuery(qname=domain, rdtype="A",want_dnssec=True),  # Querying A record for domain
        dns_server
        # DNSFlags.PdmMetric,  # Requesting PDM (Performance Diagnostic Metrics) option
    )

    # Check if a response was received
    if result:
        print(f"Latency: {result.latency_ns} ns")
        for rrset in result.response.answer:
            print(rrset)
            if rrset.rdtype == dns.rdatatype.RRSIG:
                print("✅ RRSIG record found")
        for rrset in result.response.additional:
            if rrset.rdtype == dns.rdatatype.DNSKEY:
                print("✅ DNSKEY record found")
    else:
        print("Failed to receive a response.")

    # Process additional DNS parameters if PDM option is present
    if result.additional_params:
        for option in result.additional_params:
            if option.option_type == 15:  # PDM option identifier
                pdm_option = option
                print()
                print(
                    f"PDM Option Type: 0x{pdm_option.option_type:02x} ({pdm_option.option_type})"
                )
                print(f"PDM Opt Len: 0x{pdm_option.opt_len:02x} ({pdm_option.opt_len})")
                print(f"PSNTP: 0x{pdm_option.psntp:02x} ({pdm_option.psntp})")
                print(f"PSNLR: 0x{pdm_option.psnlr:02x} ({pdm_option.psnlr})")
                print(f"DeltaTLR: 0x{pdm_option.deltatlr:02x} ({pdm_option.deltatlr})")
                print(f"DeltaTLS: 0x{pdm_option.deltatls:02x} ({pdm_option.deltatls})")
                print(
                    f"Scale DTLR: 0x{pdm_option.scale_dtlr:02x} ({pdm_option.scale_dtlr})"
                )
                print(
                    f"Scale DTLS: 0x{pdm_option.scale_dtls:02x} ({pdm_option.scale_dtls})"
                )
                print()

                # Calculate and display latency breakdown
                print("rtt: ", result.latency_ns)  # Total round-trip time (RTT)
                server_latency = _astons(pdm_option.deltatlr, pdm_option.scale_dtlr)
                print(
                    "server latency: ", server_latency
                )  # Estimated server processing latency
                print(
                    "network latency: ", result.latency_ns - server_latency
                )  # Estimated network latency
