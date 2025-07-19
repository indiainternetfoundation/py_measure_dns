import pytest
import dns.message
from measure_dns import build_dns_query, decode_dns_response, DNSQuery,send_dns_query

def test_build_dns_query():
    wire = build_dns_query("example.com", "A")
    assert isinstance(wire, bytes)
    msg = dns.message.from_wire(wire)
    assert msg.question[0].name.to_text() =="example.com."
    assert msg.question[0].rdtype == dns.rdatatype.A

def test_recursive_dns_query():
    query = DNSQuery(qname="example.com", rdtype="A")
    wire = build_dns_query(query.qname, query.rdtype)
    msg = dns.message.from_wire(wire)
    assert msg.flags & dns.flags.RD


def test_non_dns_query_bytes():
    result = decode_dns_response(b'not a dns packet')
    assert isinstance(result, dict)
    assert not isinstance(result, dns.message.Message)
    assert 'Failed to decode response' in result['error']
    

def test_decode_dns_response():
    wire = build_dns_query("example.com", "A")
    result = decode_dns_response(wire)
    assert isinstance(result, dns.message.Message)
    assert result.question[0].name.to_text() == "example.com."
    assert result.question[0].rdtype == dns.rdatatype.A

def test_decode_dns_response_wrong_type():
    with pytest.raises(Exception):
        build_dns_query("example.com", "B")

def test_dnsquery_default_flags():
    query = DNSQuery(qname="example.com", rdtype="A")
    assert query.flags == 256  

def test_build_dns_query_bytes_length():
    wire = build_dns_query("example.com", "A")
    assert len(wire) == 29

def test_dns_query_want_dnssec_false():
    query=DNSQuery(qname="example.com", rdtype="A")
    assert isinstance(query.want_dnssec, bool)
