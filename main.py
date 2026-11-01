import socket
import ssl
import argparse
import logging
import sys
from datetime import datetime, timezone
from OpenSSL import crypto

WEAK_CIPHER_TOKENS = ("RC4", "DES", "3DES", "MD5", "NULL", "EXPORT")

# Numeric ordering for the protocol versions this tool can report.
PROTOCOL_ORDER = {
    "SSLv2": 2.0,
    "SSLv3": 3.0,
    "TLSv1": 1.0,
    "TLSv1.0": 1.0,
    "TLSv1.1": 1.1,
    "TLSv1.2": 1.2,
    "TLSv1.3": 1.3,
}


def judge_protocol(protocol):
    """Return a plain judgement line for a negotiated protocol version."""
    if not protocol:
        return "Protocol: could not be determined."
    order = PROTOCOL_ORDER.get(protocol)
    if order is None:
        return f"Protocol {protocol}: unrecognized version, judged manually."
    if order < 1.2:
        return f"Protocol {protocol}: WEAK, below TLS 1.2."
    return f"Protocol {protocol}: OK, TLS 1.2 or newer."


def judge_cipher_name(cipher_name):
    """Return a flag line for a cipher name carrying a weak token, else None."""
    if not cipher_name:
        return None
    upper = str(cipher_name).upper()
    for token in WEAK_CIPHER_TOKENS:
        if token in upper:
            return f"Cipher {cipher_name}: WEAK, name carries {token}."
    return None


def judge_certificate_dates(not_before_text, not_after_text):
    """Return a plain judgement line for certificate validity dates."""
    try:
        # I only accept the compact Zulu form here. A certificate whose dates arrive in a generalised time form with an offset fails the parse and is reported as unparseable rather than judged on its actual dates.
        not_before = datetime.strptime(not_before_text, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
        not_after = datetime.strptime(not_after_text, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return "Certificate dates: could not be parsed."
    now = datetime.now(timezone.utc)
    if now < not_before:
        return "Certificate: NOT YET VALID, the not-before date is in the future."
    if now > not_after:
        return "Certificate: EXPIRED, the not-after date has passed."
    return "Certificate: within its validity dates."


def collect_judgements(analysis_results, cert_info):
    """Build the plain judgement lines for a run."""
    lines = []
    if analysis_results:
        lines.append(judge_protocol(analysis_results.get("protocol")))
        cipher = analysis_results.get("cipher")
        if cipher:
            flag = judge_cipher_name(cipher[0])
            if flag:
                lines.append(flag)
            else:
                lines.append(f"Cipher {cipher[0]}: no weak token in its name.")
        supported = analysis_results.get("supported_ciphers")
        if isinstance(supported, list):
            for name in supported:
                flag = judge_cipher_name(name)
                if flag:
                    lines.append(flag)
    if cert_info:
        lines.append(judge_certificate_dates(cert_info.get("not_before"), cert_info.get("not_after")))
    return lines

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Analyzes TLS/SSL configuration of a given server.")
    parser.add_argument("hostname", help="The hostname or IP address of the server to analyze.")
    parser.add_argument("-p", "--port", type=int, default=443, help="The port number to connect to (default: 443).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    parser.add_argument("-c", "--check-cert", action="store_true", help="Check certificate validity")
    return parser.parse_args()


def check_certificate(hostname, port=443):
    """
    Checks the validity and other attributes of the server's TLS certificate.
    Args:
        hostname (str): The hostname or IP address of the server.
        port (int): The port number to connect to (default: 443).

    Returns:
        dict: A dictionary containing certificate information, or None if an error occurs.
    """
    try:
        # Because this is a default verifying context, a certificate that is expired, self signed, or chained to an unknown root fails the handshake itself and I return None. The date judgement further down therefore only ever runs on certificates that already passed verification.
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)

                cert_info = {
                    # Folding the components into a dict drops repeated fields: a subject with two OU entries keeps only the last one. The keys also stay as bytes, which is why the printed subject shows b'CN' style labels.
                    'subject': dict(x509.get_subject().get_components()),
                    'issuer': dict(x509.get_issuer().get_components()),
                    'version': x509.get_version(),
                    'serial_number': x509.get_serial_number(),
                    'not_before': x509.get_notBefore().decode('utf-8'),
                    'not_after': x509.get_notAfter().decode('utf-8'),
                    'extensions': [str(x509.get_extension(i)) for i in range(x509.get_extension_count())]
                }
                return cert_info

    except socket.gaierror as e:
        logging.error(f"Error resolving hostname: {e}")
        return None
    except ssl.SSLError as e:
        logging.error(f"SSL Error: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

def analyze_tls_configuration(hostname, port=443):
    """
    Analyzes the TLS/SSL configuration of a given server.

    Args:
        hostname (str): The hostname or IP address of the server.
        port (int): The port number to connect to (default: 443).

    Returns:
        dict: A dictionary containing analysis results.
    """

    results = {}
    try:
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                results['protocol'] = ssock.version()
                results['cipher'] = ssock.cipher()

                # Get supported cipher suites (This might require a more complex approach with various SSLContext settings)
                try:
                    # Shared ciphers means the overlap between this client and that server on this one connection, not the server's full supported list. A cipher the server offers that my own OpenSSL build lacks never appears, so I do not present this list as the server's whole capability.
                    supported_ciphers = ssock.shared_ciphers() #Available from Python 3.7+
                    if supported_ciphers is None:
                        results['supported_ciphers'] = "Unavailable"
                    else:
                        results['supported_ciphers'] = [cipher[0] for cipher in supported_ciphers]
                except AttributeError:
                    logging.warning("Cannot retrieve shared ciphers. Requires Python 3.7+ and properly negotiated connection.")
                    results['supported_ciphers'] = "Unavailable"

        return results

    except socket.gaierror as e:
        logging.error(f"Error resolving hostname: {e}")
        return None
    except ssl.SSLError as e:
        logging.error(f"SSL Error: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

def main():
    """
    Main function to execute the TLS/SSL analyzer.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logging.info(f"Starting TLS analysis for {args.hostname}:{args.port}")

    # Validate input
    try:
        socket.inet_aton(args.hostname) # Check if the hostname is a valid IP address
    except socket.error:
        pass  # It's not an IP address, assume it's a hostname
    
    if not isinstance(args.port, int) or not (1 <= args.port <= 65535):
        logging.error("Invalid port number. Port must be an integer between 1 and 65535.")
        sys.exit(1)

    analysis_results = analyze_tls_configuration(args.hostname, args.port)
    failed = False

    if analysis_results:
        print("\nTLS/SSL Configuration Analysis:")
        print(f"  Protocol: {analysis_results.get('protocol', 'N/A')}")
        print(f"  Cipher: {analysis_results.get('cipher', 'N/A')}")
        print(f"  Supported Ciphers: {analysis_results.get('supported_ciphers', 'N/A')}")
    else:
        print("Failed to retrieve TLS/SSL configuration.")
        failed = True

    cert_info = None
    if args.check_cert:
        # This opens a second, separate handshake from the analysis connection above. A server that rotates certificates or answers differently per connection can give me a protocol from one certificate's session and dates from another, and the assessment section then mixes the two.
        cert_info = check_certificate(args.hostname, args.port)
        if cert_info:
            print("\nCertificate Information:")
            print(f"  Subject: {cert_info['subject']}")
            print(f"  Issuer: {cert_info['issuer']}")
            print(f"  Version: {cert_info['version']}")
            print(f"  Serial Number: {cert_info['serial_number']}")
            print(f"  Not Before: {cert_info['not_before']}")
            print(f"  Not After: {cert_info['not_after']}")
            print(f"  Extensions: {cert_info['extensions']}")
        else:
            print("Failed to retrieve certificate information.")
            failed = True

    if analysis_results or cert_info:
        judgements = collect_judgements(analysis_results, cert_info)
        if judgements:
            print("\nAssessment:")
            for line in judgements:
                print(f"  {line}")

    if failed:
        sys.exit(1)

if __name__ == "__main__":
    main()