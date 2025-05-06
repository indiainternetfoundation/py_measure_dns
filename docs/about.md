# About

## About `measure_dns`

**`measure_dns`** is a Python package designed to facilitate low-level DNS performance measurements using a combination of Python and high-speed native C extensions. This library enables:

- Fine-grained control over DNS query construction and transmission
- Measurement of DNS latency at the network layer
- Extraction and parsing of IPv6 Extension Headers, especially the Performance and Diagnostic Metrics (PDM) Option
- Integration with experimental setups for research, benchmarking, and diagnostics

This package was developed as a **byproduct of research and implementation work presented by the [India Internet Foundation](https://iifon.org/)** during the **IETF 122 Hackathon**. At the event, the team from IIFON demonstrated the performance of different DNS server software implementations over IPv6 using PDM Options.

---

## Why `measure_dns`?

With increasing complexity in DNS resolution behavior—due to CDNs, encrypted DNS, and hybrid IPv4/IPv6 infrastructures, network practitioners and researchers need visibility at the protocol level. `measure_dns` helps uncover:

- **Real-world latency patterns**
- **Edge behavior of DNS resolvers**
- **Routing and timing inconsistencies**
- **Impact of IPv6 headers and transport-level flags**

> 🔬 Whether you're an academic, policy maker, or systems engineer, `measure_dns` gives you the ability to **observe what resolvers see**, and **measure performance in a reproducible, programmatic way**.

---

## About India Internet Foundation

**India Internet Foundation (IIFON)** is a nonprofit organization working to **strengthen India’s core Internet backbone** through open collaboration, public infrastructure, and standards-aligned software systems.

### 🎯 Our Mission

- Build **resilient, standards-compliant national internet infrastructure**
- Provide **open-access, verifiable internet measurements**
- Support development and deployment of **secure, sovereign DNS** and **IPv6-native stacks**
- Foster **technical capacity-building and open standards participation**

### 🛠️ Our Focus Areas

- **DNS Infrastructure**: Including root zone mirrors, sovereign resolvers, DNSSEC, and more
- **IPv6 Protocols and Adoption**: Protocols, Tools, Workshops, and real-world deployment
- **Public Key Infrastructure (PKI)**: Community-trusted cert infrastructure and transparency for DNS and Routing
- **Standards Development**: Active participation and contributions to bodies like the IETF and ISOC
- **Education and Outreach**: Hackathons, fellowships, and academic-industry partnerships

---

## Getting Involved

India Internet Foundation invites developers, researchers, students, and institutions to collaborate and build critical internet tools with us.

> 💬 For project contributions, volunteering, or partnerships, visit **[https://iifon.org/](https://iifon.org/)** or explore our GitHub organization: **[https://github.com/indiainternetfoundation](https://github.com/indiainternetfoundation)**

---
