import socket
import ssl
import argparse
import logging
import sys
from OpenSSL import crypto

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
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)

                cert_info = {
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
                    supported_ciphers = ssock.shared_ciphers() #Available from Python 3.7+
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

    if analysis_results:
        print("\nTLS/SSL Configuration Analysis:")
        print(f"  Protocol: {analysis_results.get('protocol', 'N/A')}")
        print(f"  Cipher: {analysis_results.get('cipher', 'N/A')}")
        print(f"  Supported Ciphers: {analysis_results.get('supported_ciphers', 'N/A')}")
    else:
        print("Failed to retrieve TLS/SSL configuration.")

    if args.check_cert:
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

if __name__ == "__main__":
    main()