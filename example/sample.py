import socket
from measure_dns import DNSQuery, send_dns_query, DNSFlags

def _astons(delta, scale):
    ns_time = delta
    ns_time = int(ns_time) << (scale - 8)

    ns_time *= 16*16
    ns_time /= 10000
    ns_time /= 100000
    return int(ns_time)

if __name__ == "__main__":
    domain = "testprotocol.in"
    dns_server = "2406:da1a:8e8:e8cb:97fe:3833:8668:54ad" # ns2.testprotocol.in
    # dns_server = "65.0.92.216" # ns2.testprotocol.in
    # dns_server = "13.127.175.92" # ns1.testprotocol.in

    result = send_dns_query(
        DNSQuery(qname=domain, rdtype="A"),
        dns_server,
        DNSFlags.PdmMetric
    )

    if result:
        print(f"Latency: {result.latency_ns} ns")
        print(result.response.answer)
    else:
        print("Failed to get a response.")
    
    if result.additional_params:
        for option in result.additional_params:
            if option.option_type == 15:
                pdm_option = option
                print()
                print(f"PDM Option Type: 0x{pdm_option.option_type:02x} ({pdm_option.option_type})")
                print(f"PDM Opt Len: 0x{pdm_option.opt_len:02x} ({pdm_option.opt_len})")
                print(f"PSNTP: 0x{pdm_option.psntp:02x} ({pdm_option.psntp})")
                print(f"PSNLR: 0x{pdm_option.psnlr:02x} ({pdm_option.psnlr})")
                print(f"DeltaTLR: 0x{pdm_option.deltatlr:02x} ({pdm_option.deltatlr})")
                print(f"DeltaTLS: 0x{pdm_option.deltatls:02x} ({pdm_option.deltatls})")
                print(f"Scale DTLR: 0x{pdm_option.scale_dtlr:02x} ({pdm_option.scale_dtlr})")
                print(f"Scale DTLS: 0x{pdm_option.scale_dtls:02x} ({pdm_option.scale_dtls})")
                print()
                print("rtt: ", result.latency_ns)
                print("server latency: ", _astons(pdm_option.deltatlr, pdm_option.scale_dtlr))
                print("network latency: ", result.latency_ns - _astons(pdm_option.deltatlr, pdm_option.scale_dtlr))

