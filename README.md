# openssl-cert-exporter
Prometheus Exporter for OpenSSL

```
Usage: openssl-cert-exporter [-p PORT -c CONFIG]

Options:
  -h, --help            show this help message and exit
  -c CONFIG, --config=CONFIG
                        Path to the config path. Default value: ./config.yml
  -p PORT, --port=PORT  Port to run on. Default value: 9997
```

The configuration file is a YAML containing a list of an objects containing at least valid "type" and "path keys".
The current supported certificate types are `x509` and `crl` and the path should be readable by the user running the exporter.

Example of a valid configuration:
```yaml
---
- type: x509
  path: /usr/share/ca-certificates/mozilla/e-Szigno_Root_CA_2017.crt
```
