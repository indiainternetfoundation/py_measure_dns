#  DNS Request with DNSSEC & Response Validation (Using 8.8.8.8)

##  What is DNSSEC?

**DNSSEC** (Domain Name System Security Extensions) adds **security** to DNS by verifying that DNS responses haven’t been **tampered with**. It does this using **digital signatures** attached to DNS records.

👉 Learn more here: [What is DNSSEC? (Cloudflare)](https://www.cloudflare.com/learning/dns/dnssec/)

---

##  How `measuredns` Supports DNSSEC

When you run a DNS query using `measuredns`, you can **enable DNSSEC** by setting the `DO` (**DNSSEC OK**) bit in the query. This tells the DNS server to include **DNSSEC-related records** (like `DNSKEY` and `RRSIG`) in the response.

In our tool, this is done using the `DNSQuery` class with `want_dnssec=True`.

We use **Google Public DNS (8.8.8.8)** which supports DNSSEC.

---

##  How to Send a DNSSEC-enabled Query

```python
result = send_dns_query(
    DNSQuery(qname="cloudflare.com", rdtype="A", want_dnssec=True),
    "8.8.8.8"
)

```
### Output

```bash
Latency: 94121290.0 ns
cloudflare.com. 619 IN DNSKEY 256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWz JaOau8XNEZeqCYKD5ar0IRd8KqXXFJkq mVfRvMGPmM1x8fGAa2XhSA==
cloudflare.com. 619 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0d xCjjnopKl+GqJxpVXckHAeF+KkxLbxIL fDLUT0rAK9iUzy1L53eKGQ==
cloudflare.com. 619 IN RRSIG DNSKEY 13 2 3600 20250820045444 20250620045444 2371 cloudflare.com. cttiL9pyC8QvCXsG6x3lDaix7y9NRiNY 2A+8YovhAbmpRvuEGChMSSYific7AJQw cvqjj3NPtDIjTaKN9y370g==
✅ RRSIG record found
```
