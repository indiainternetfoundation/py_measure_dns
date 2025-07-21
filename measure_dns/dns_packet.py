import ctypes
import enum
import struct
import typing
from dataclasses import dataclass
from ipaddress import IPv4Address, ip_address
import dns.message
import dns.name
import dns.rdataclass
from dns.rdataclass import RdataClass
from .native import dns_lib, DNSResponse, AdditionalParam, PDMOption, DestOptHdr
class DNSFlags(enum.IntEnum):
    """
    DNSFlags represent bitmask values to control extended DNS query behaviors.

    These flags are passed into the native `measuredns` C library to enable additional
    metrics collection, pre-resolution of DNS server addresses, or inclusion of PDM metrics.

    Attributes:
        NoFlag (int): No additional behavior.
        PdmMetric (int): Include Performance Diagnostic Metrics (PDM) in the query.
        PreResolve4 (int): Resolve the DNS server domain to an IPv4 address before querying.
        PreResolve6 (int): Resolve the DNS server domain to an IPv6 address before querying.

    Example:
        ```py
        from measure_dns import DNSFlags
        flags = DNSFlags.PdmMetric | DNSFlags.PreResolve4 # (1)
        print(flags)
        ```

        1. This example code snippet will add the PDM Extension Header in the final IPv6 Packet, and send the query to the  IPv4 Addresss of the DNS server

    Note:
        These are internal flags for the C-extension layer and not part of the standard DNS protocol.
    """

    NoFlag = 0x0000
    PdmMetric = 0x0001
    PreResolve4 = 0x0010  # Resolves the DNS Server domain IPv4
    PreResolve6 = 0x0100  # Resolves the DNS Server domain IPv6
    # DummyFlagB = 0x1000


@dataclass
class DNSQuery:
    """
    Represents a full specification of a DNS query object, including all
    customization knobs.

    This structure wraps everything needed to construct a complete query,
    including EDNS options, flags, and DNSSEC capabilities. This object
    can be passed to `send_dns_query` for low-level querying.

    Attributes:
        qname (str or Name): The query name.
        rdtype (str or RdataType): The record type (e.g., A, AAAA).
        rdclass (str or RdataClass): The record class (default: IN).
        use_edns (bool|int): Whether to use EDNS.
        want_dnssec (bool): Whether to request DNSSEC support.
        ednsflags (int): Optional EDNS flags.
        payload (int): EDNS payload size.
        request_payload (int): Requested payload size.
        options (list): Optional EDNS options.
        idna_codec (IDNACodec): Codec for internationalized domain names.
        id (int): Query ID.
        flags (int): DNS flags field (default 256).
        pad (int): Padding bytes for EDNS0.

    Example:
        ```py
        from measure_dns import DNSQuery, send_dns_query
        query = DNSQuery(qname="example.com", rdtype="A", want_dnssec=True)
        result = send_dns_query(query, "8.8.8.8")
        ```
    """

    qname: typing.Union[dns.name.Name, str]
    rdtype: typing.Union[dns.rdatatype.RdataType, str]
    rdclass: typing.Union[dns.rdataclass.RdataClass, str] = RdataClass.IN
    use_edns: typing.Union[int, bool, None] = None
    want_dnssec: bool = True
    ednsflags: typing.Union[int, None] = None
    payload: typing.Union[int, None] = None
    request_payload: typing.Union[int, None] = None
    options: typing.Union[typing.List[dns.edns.Option], None] = None
    idna_codec: typing.Union[dns.name.IDNACodec, None] = None
    id: typing.Union[int, None] = None
    flags: int = 256
    pad: int = 0


@dataclass
class DNSResult:
    """
    Represents the parsed result of a DNS query. Encapsulates the result
    of a DNS query made using the native C-extension

    Attributes:
        response (dns.message.Message): Decoded DNS response.
        latency_ns (float): Round-trip time in nanoseconds.
        additional_params (list): Parsed PDM or diagnostic options.
    """

    response: dns.message.QueryMessage
    latency_ns: float
    additional_params: list


def send_dns_query(
    query: DNSQuery, dns_server: str, extra_flags: DNSFlags = 0
) -> DNSResult:
    """
    Sends a DNS query to the specified server and returns the response.

    Sends a DNS query using the native `measuredns` C extension and collects response metrics. It
    uses `build_dns_query` to generate the wire format. converts the query into a C-compatible
    format via `ctypes`. Then calls the `query_dns` function from the compiled shared object.
    It then extracts latency and any additional diagnostics (e.g., PDM) and parses the binary
    response back into a `dns.message.QueryMessage`.

    Args:
        query (DNSQuery): The DNS query to send.
        dns_server (str): The target DNS server IP or hostname.
        extra_flags (DNSFlags): Additional control flags (e.g., for metrics or pre-resolve).

    Returns:
        DNSResult: Decoded DNS response, latency, and any additional parameters.

    Example:
        ```py
        from measure_dns import DNSQuery, send_dns_query
        query = DNSQuery(qname="example.com", rdtype="A")
        result = send_dns_query(query, "1.1.1.1", DNSFlags.PdmMetric)
        print(result.latency_ns)
        ```

    Note:
        This function may return `None` if the native C-layer call fails.
    """
    request = build_dns_query(
        qname=query.qname,
        rdtype=query.rdtype,
        rdclass=query.rdclass,
        use_edns=query.use_edns,
        want_dnssec=query.want_dnssec,
        ednsflags=query.ednsflags,
        payload=query.payload,
        request_payload=query.request_payload,
        options=query.options,
        idna_codec=query.idna_codec,
        id=query.id,
        flags=query.flags,
        pad=query.pad,
    )
    request_size = len(request)

    request_ctypes = (ctypes.c_ubyte * request_size)(*request)
    dns_server_ctypes = ctypes.c_char_p(dns_server.encode())

    use_ipv6_ctypes = ctypes.c_int(
        0 if type(ip_address(dns_server)) is IPv4Address else 1
    )
    extra_flags_ctypes = ctypes.c_int(extra_flags)

    response_struct = DNSResponse()
    response_struct.num_additional_params = 0
    response_size = dns_lib.query_dns(
        dns_server_ctypes,
        request_ctypes,
        request_size,
        ctypes.byref(response_struct),
        use_ipv6_ctypes,
        extra_flags_ctypes,
    )
    additional_params_list = []
    for i in range(response_struct.num_additional_params):
        params = response_struct.additional_params[i]
        if params.type == 59:
            # Destination Option
            dstopt = ctypes.cast(params.data, ctypes.POINTER(DestOptHdr)).contents

            # Extract PDM Option (first 10 bytes of options)
            pdm_raw = bytes(dstopt.options[:12])

            # Cast the extracted bytes into a PDMOption structure
            pdm_option = PDMOption.from_buffer_copy(pdm_raw)
            additional_params_list.append(pdm_option)

    if response_size > 0:
        return DNSResult(
            response=decode_dns_response(
                bytes(response_struct.response[:response_size])
            ),
            latency_ns=response_struct.latency_ns,
            additional_params=additional_params_list,
        )
    else:
        return None


def decode_dns_response(response_bytes) -> dns.message.QueryMessage:
    """
    Decodes a raw DNS response from wire format.

    Args:
        response_bytes (bytes): Wire-format DNS response.

    Returns:
        QueryMessage: Parsed DNS response.

    Example:
        ```py
        from measure_dns import decode_dns_response
        resp = decode_dns_response(wire_response)
        print(resp.answer)
        [<DNS answer RRset example.com. IN A 93.184.216.34>]
        ```

    Note:
        If parsing fails, a dictionary with the error message is returned.
    """
    try:
        message = dns.message.from_wire(response_bytes)
        return message

    except Exception as e:
        return {"error": f"Failed to decode response: {e}"}


def build_dns_query(
    qname: typing.Union[dns.name.Name, str],
    rdtype: typing.Union[dns.rdatatype.RdataType, str],
    rdclass: typing.Union[dns.rdataclass.RdataClass, str] = RdataClass.IN,
    use_edns: typing.Union[int, bool, None] = None,
    want_dnssec: bool = False,
    ednsflags: typing.Union[int, None] = None,
    payload: typing.Union[int, None] = None,
    request_payload: typing.Union[int, None] = None,
    options: typing.Union[typing.List[dns.edns.Option], None] = None,
    idna_codec: typing.Union[dns.name.IDNACodec, None] = None,
    id: typing.Union[int, None] = None,
    flags: int = 256,
    pad: int = 0,
) -> bytes:
    """
    Builds a raw DNS query packet using dnspython.

    Constructs a raw binary DNS query packet using `dnspython`. This function
    supports advanced EDNS options and is suitable for precise control over
    the query wire format.

    Args:
        qname: Query name.
        rdtype: Record type (A, AAAA, etc.).
        rdclass: Record class.
        use_edns: Whether to use EDNS.
        want_dnssec: Request DNSSEC.
        ednsflags: EDNS-specific flags.
        payload: Payload size.
        request_payload: Requested payload size.
        options: EDNS options.
        idna_codec: IDNA codec for qname.
        id: Query ID.
        flags: DNS flags.
        pad: Padding bytes.

    Returns:
        bytes: Raw wire-format DNS query.

    Example:
        ```py
        from measure_dns import build_dns_query
        wire = build_dns_query("example.com", "A")
        print(wire)
        ```

    Note:
        This function does not send the query; it only serializes it.
    """
    query = dns.message.make_query(
        qname=qname,
        rdtype=rdtype,
        rdclass=rdclass,
        use_edns=use_edns,
        want_dnssec=want_dnssec,
        ednsflags=ednsflags,
        payload=payload,
        request_payload=request_payload,
        options=options,
        idna_codec=idna_codec,
        id=id,
        flags=flags,
        pad=pad,
    )

    return query.to_wire()
