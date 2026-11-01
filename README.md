# net-tls-analyzer
Analyzes TLS/SSL configuration of a given server, checking for vulnerable ciphers, certificate validity, and protocol versions. Uses `ssl` library. - Focused on Basic network operations

## Install
`git clone https://github.com/ShadowStrikeHQ/net-tls-analyzer`

Install the requirements with `pip install -r requirements.txt`. The certificate parsing uses pyOpenSSL (the `OpenSSL` package).

## Usage
`python3 main.py <hostname> [params]`

Example: `python3 main.py example.com -p 443 --check-cert`

## Parameters
- `hostname`: The hostname or IP address of the server to analyze (positional, required).
- `-h, --help`: Show help message and exit
- `-p, --port`: The port number to connect to (default: 443).
- `-v, --verbose`: Enable verbose output (debug logging).
- `-c, --check-cert`: Check certificate validity.

## Assessment checks
The tool prints plain judgements next to the values it reports:

- Protocol: a negotiated protocol below TLS 1.2 is flagged as weak.
- Certificate dates: a certificate that has expired, or whose not-before date is still in the future, is flagged.
- Cipher names: a negotiated or shared cipher whose name carries a weak token (RC4, DES, 3DES, MD5, NULL, or EXPORT) is flagged.

If the server returns no shared cipher list, the supported ciphers field reports Unavailable and the rest of the analysis is kept.

## Exit status
The run exits with status 1 when the TLS analysis returns nothing, and when a certificate check was requested with `--check-cert` and returns nothing. A run that retrieved results exits with status 0.

## License
Copyright (c) ShadowStrikeHQ
