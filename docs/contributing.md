# Contributing to `measure_dns`

Welcome! We're excited you're interested in contributing to **`measure_dns`**, a low-level DNS measurement library using Python and a native C extension. This guide will help you get started and explain the standards and practices we follow.

---

## Getting Started

We welcome contributions of all kinds! Whether you're fixing bugs, writing documentation, improving tests, or proposing new features, we value your help.

**Requirements**:

- Python 3.8+
- Git
- C compiler (e.g. GCC or Clang)
- `pip` for dependency management

=== "Install from local source"
    ```bash
    # Clone the repo
    $ git clone https://github.com/indiainternetfoundation/measure_dns.git
    $ cd measure_dns

    # Install the package
    $ pip install .
    ```

=== "Install from remote source"
    ```bash
    # Install the package directly from github
    $ pip install git+https://github.com/indiainternetfoundation/py_measure_dns
    ```


---

## Types of Contributions

You can contribute in multiple ways:

- **Code contributions**: Fix bugs or add features.
- **Documentation**: Help keep the documentation up to date.
- **Tests**: Improve test coverage or test edge cases.
- **Examples**: Add real-world usage examples.
- **Issue triage**: Help manage open issues.

---

## Setting Up for Development

Clone and install the project in editable mode:

```bash
$ git clone https://github.com/indiainternetfoundation/measure_dns.git
$ cd measure_dns

$ pip install -e ".[develop]"
```

To build the native extension in-place:

```bash
$ gcc -shared -fPIC -fno-strict-overflow -Wsign-compare -DNDEBUG -g -O2 -Wall -o measure_dns/measuredns.so measure_dns/measuredns.c
```

---

## How to Make a Pull Request

1. Fork the repository.
2. Create a feature branch:
   ```bash
   $ git checkout -b feature/my-awesome-feature
   ```
3. Make your changes.
4. Write tests and update docs.
5. Commit and push:
   ```bash
   $ git commit -m "Add my awesome feature"
   $ git push origin feature/my-awesome-feature
   ```
6. Open a pull request on GitHub.
7. Fill out the PR template and request review.

---

## Code Style Guide

We follow [PEP8](https://pep8.org) with minor customizations:

- Use `black` for formatting:
  ```bash
  $ black -v -t py312 .
  ```

- Use `isort` for import sorting:
  ```bash
  $ isort .
  ```

- Type annotations are **required**.
- Docstrings must follow the [Google style](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings). Below is an example function definition with docstrings.

```python
def resolve(domain: str) -> str:
    """
    Resolve a domain to its IP address.

    Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod 
    tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, 
    quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo 
    consequat.

    Attributes:
        domain (str): A valid QName of a domain to resolve for.

    Note:
        Duis aute irure dolor in reprehenderit in voluptate velit esse cillum 
        dolore eu fugiat nulla pariatur.
    """
    resolver = choose_best_resolver(["1.1.1.1", "8.8.8.8", "9.9.9.9"])
    ipv4_resolution = resolve_from_resolver(domain, "A", resolver)
    ipv6_resolution = resolve_from_resolver(domain, "AAAA", resolver)
    return [*ipv4_resolution, *ipv6_resolution]
```


---

## Writing and Running Tests

All tests are located in the `tests/` directory.

Run tests with:

```bash
$ pytest
```

**Example test:**

```python
def test_simple_dns_query():
    result = send_dns_query(DNSQuery(qname="example.com", rdtype="A"), "1.1.1.1")
    assert result is not None
    assert result.response.rcode() == 0
```

---

## Docstrings & Documentation

All public functions and classes must have detailed docstrings using reStructuredText or Google style.

For user-facing docs:

- We use **MkDocs with Material Theme**.
- Documentation is under `docs/`.

To build:

```bash
$ mkdocs serve
```

---

## Native Extension Notes

The native extension (`measuredns.c`) uses `ctypes` and is precompiled.

Key files:

- `src/measuredns.c`: Contains the C code.
- `src/measure_dns/__init__.py`: `ctypes` bindings.

If you add a new C function:

1. Declare it in the header.
2. Define it in `measuredns.c`.
3. Add its binding in `__init__.py`.
4. Update tests.

---

## Community and Support

- Open an [Issue](https://github.com/indiainternetfoundation/measure_dns/issues)
- Join our Discussions
- Email the maintainer: `arnav.das@iifon.net`

Thank you for contributing!

---

_Made with care for internet engineering and research enthusiasts._