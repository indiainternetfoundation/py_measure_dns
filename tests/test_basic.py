import pytest
from dns.rdatatype import A

from measure_dns import DNSQuery, send_dns_query

# Mock DNS server — replace with a controlled test server if needed
TEST_DNS_SERVER = "8.8.8.8"  # or use a mock server / local resolver


def test_dns_query_construction():
    qname = "example.com"
    query = DNSQuery(qname=qname, rdtype="A")
    assert query.qname == qname
    assert query.rdtype == "A"


def test_send_dns_query_success():
    query = DNSQuery(qname="example.com", rdtype="A")
    result = send_dns_query(query, TEST_DNS_SERVER)
    assert result is not None
    assert result.latency_ns > 0
    assert hasattr(result.response, "answer")
    assert any(rr.rdtype == A for rr in result.response.answer)


# def test_send_dns_query_invalid_domain():
#     query = DNSQuery(qname="nonexistentdomain.abcxyz", rdtype="A")
#     result = send_dns_query(query, TEST_DNS_SERVER)
#     assert result is not None
#     assert result.latency_ns > 0
    # We expect no answer for invalid domain
#     assert len(result.response.answer) == 0


# def test_send_dns_query_invalid_server():
#     query = DNSQuery(qname="example.com", rdtype="A")
#     # Use an unreachable IP to simulate failure
#     invalid_server = "192.0.2.1"
#     result = send_dns_query(query, invalid_server)
#     assert result is None
