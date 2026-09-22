import socket
import ssl
import argparse
from ast import literal_eval
import datetime
import ipaddress
import os
import signal  # Required for POSIX SIGPIPE handling

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ObjectIdentifier

# Ignore SIGPIPE on POSIX systems so broken client connections don't terminate Python
if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

class TlsServer():

    def __init__(self, *args, **kwargs):
        self.host = kwargs.pop("host", "127.0.0.1")
        self.port = kwargs.pop("port", 50000)
        self.server = None
        self.end = False
        self.context = None

        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.host, self.port))
            print("# tls dummy_server started: ", self.host, self.port, flush=True)
            self.server.listen()
        except Exception as e:
            print("Couldn't start tls_server", flush=True)
            print(e, flush=True)

    def check_server(self):
        if not self.server:
            raise Exception("Server not started")

    def send_server_hello(self, conn):
        self.check_server()
        try:
            conn.sendall(server_hello)
        except Exception as e:
            print("Couldn't send server_hello", flush=True)
            print(e, flush=True)
            return 0
        return 1

    def generate_cert(self,
                      create_new=False,
                      cert_mode="self_signed",
                      create_crl=False,
                      emailAddress="emailAddress",
                      commonName="commonName",
                      SAN=None,
                      countryName="NT",
                      localityName="localityName",
                      stateOrProvinceName="stateOrProvinceName",
                      organizationName="organizationName",
                      organizationUnitName="organizationUnitName",
                      serialNumber=123,
                      custom_critical_ext=False,
                      validityStartInSeconds=0,
                      validityEndInSeconds=10*365*24*60*60,
                      KEY_FILE="privkey.pem",
                      CRL_FILE="selfsigned.crl",
                      CERT_FILE="selfsigned.pem",
                      CA_FILE="ca.pem",
                      CA_KEY_FILE="ca.key"):

        self.key_file = KEY_FILE
        self.cert_file = CERT_FILE
        self.crl_file = CRL_FILE
        self.ca_file = CA_FILE

        if create_new:
            try:
                # 1. Generate Server Private Key
                k = rsa.generate_private_key(public_exponent=65537, key_size=2048)

                # Set validity window
                now = datetime.datetime.now(datetime.timezone.utc)
                not_before = now + datetime.timedelta(seconds=validityStartInSeconds)
                not_after = now + datetime.timedelta(seconds=validityEndInSeconds)

                # Always include IP SANs for local loopback so CONC-846 verification passes
                san_names = [
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.IPAddress(ipaddress.ip_address("::1")),
                    x509.DNSName("localhost")
                ]

                # Subject Alternative Name parsing
                if SAN:
                    for entry in SAN.split(","):
                        entry = entry.strip()
                        if entry.startswith("IP:") or entry.startswith("IP.1:"):
                            ip_str = entry.split(":", 1)[1]
                            san_names.append(x509.IPAddress(ipaddress.ip_address(ip_str)))
                        elif entry.startswith("DNS:"):
                            dns_str = entry.split(":", 1)[1]
                            san_names.append(x509.DNSName(dns_str))
                        else:
                            san_names.append(x509.DNSName(entry))
                elif commonName and commonName != "commonName":
                    san_names.append(x509.DNSName(commonName))

                san_ext = x509.SubjectAlternativeName(san_names)

                # Branch A: Standard Self-Signed Cert
                if cert_mode == "self_signed":
                    subject = issuer = x509.Name([
                        x509.NameAttribute(NameOID.COUNTRY_NAME, countryName),
                        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, stateOrProvinceName),
                        x509.NameAttribute(NameOID.LOCALITY_NAME, localityName),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organizationName),
                        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizationUnitName),
                        x509.NameAttribute(NameOID.COMMON_NAME, commonName),
                        x509.NameAttribute(NameOID.EMAIL_ADDRESS, emailAddress),
                    ])

                    builder = (
                        x509.CertificateBuilder()
                        .subject_name(subject)
                        .issuer_name(issuer)
                        .public_key(k.public_key())
                        .serial_number(serialNumber)
                        .add_extension(san_ext, critical=False)
                    )

                    if custom_critical_ext:
                        print("# setting custom_critical_ext", flush=True)
                        dummy_oid = ObjectIdentifier("1.3.6.1.4.1.99999.1.1")
                        builder = builder.add_extension(
                            x509.UnrecognizedExtension(dummy_oid, b"invalid_critical_data"),
                            critical=True
                    )

                    builder._not_valid_before = not_before
                    builder._not_valid_after = not_after
                    cert = builder.sign(k, hashes.SHA256())

                    with open(CERT_FILE, "wb") as f:
                        f.write(cert.public_bytes(serialization.Encoding.PEM))
                    with open(KEY_FILE, "wb") as f:
                        f.write(k.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                            encryption_algorithm=serialization.NoEncryption()
                        ))
                    return 1

                # Branch B: CA-Signed Leaf Certificate
                ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                ca_subject = x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, "fake-mysqld throwaway CA")
                ])
                ca_builder = (
                    x509.CertificateBuilder()
                    .subject_name(ca_subject)
                    .issuer_name(ca_subject)
                    .public_key(ca_key.public_key())
                    .serial_number(1)
                    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                )
                ca_builder._not_valid_before = not_before
                ca_builder._not_valid_after = not_after
                ca_cert = ca_builder.sign(ca_key, hashes.SHA256())

                leaf_subject = x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, commonName)
                ])
                leaf_builder = (
                    x509.CertificateBuilder()
                    .subject_name(leaf_subject)
                    .issuer_name(ca_subject)
                    .public_key(k.public_key())
                    .serial_number(serialNumber)
                    .add_extension(san_ext, critical=False)
                )

                leaf_builder._not_valid_before = not_before
                leaf_builder._not_valid_after = not_after
                leaf_cert = leaf_builder.sign(ca_key, hashes.SHA256())

                with open(CA_FILE, "wb") as f:
                    f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
                with open(CA_KEY_FILE, "wb") as f:
                    f.write(ca_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    ))

                with open(CERT_FILE, "wb") as f:
                    f.write(leaf_cert.public_bytes(serialization.Encoding.PEM))
                    if cert_mode == "fullchain":
                        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

                with open(KEY_FILE, "wb") as f:
                    f.write(k.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    ))

                return 1

            except Exception as e:
                print("Error generating certs:", e, flush=True)
                return 0

        return 1

    def set_tls_context(self, reply):
        kwargs = {}
        if len(reply) > 0:
            cmds = reply.decode()
            kwargs = dict((k, literal_eval(v)) for k, v in (pair.split('=') for pair in cmds.split()))
        print("# command: ", kwargs, flush=True)
        if self.generate_cert(**kwargs):
            print("# loading certs", self.cert_file, self.key_file, flush=True)
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.load_cert_chain(self.cert_file, self.key_file)
            return 1
        return 0

    def accept(self):
        self.check_server()
        conn, addr = self.server.accept()
        return (conn, addr)

    def run(self):
        while not self.end:
            print("# Waiting for accept()...", flush=True)
            connection, address = self.accept()
            print(f"# Accepted connection from {address}", flush=True)

            # Set a 5-second socket timeout on POSIX & Windows to prevent wrap_socket() hangs
            connection.settimeout(5.0)

            try:
                print("# Sending server hello...", flush=True)
                if not self.send_server_hello(connection):
                    print("# Failed to send server hello", flush=True)
                    connection.close()
                    continue

                print("# Waiting for initial client packet (CMD/SSLRequest)...", flush=True)
                reply = connection.recv(4096)
                if not reply:
                    print("# Client closed connection before sending data", flush=True)
                    connection.close()
                    continue

                print(f"# Received packet ({len(reply)} bytes): {reply[:10]}...", flush=True)

                if reply[:4] == b'CMD:':
                    print("# Handling CMD request...", flush=True)
                    if self.set_tls_context(reply[4:]):
                        connection.sendall(b'OK')
                        print("# Sent OK response to CMD", flush=True)
                    connection.close()
                    continue

                elif reply[:4] == b'QUIT':
                    print("# Exiting tls_dummy_server", flush=True)
                    try:
                        connection.close()
                    except Exception:
                        pass
                    return

                else:
                    print("# Starting TLS wrap_socket()...", flush=True)
                    if not self.context:
                        print("# ERROR: SSLContext is None!", flush=True)
                        connection.close()
                        continue

                    tls_sock = None
                    try:
                        tls_sock = self.context.wrap_socket(connection, server_side=True)
                        print("# TLS handshake completed successfully on server side", flush=True)

                    except (ssl.SSLEOFError, ssl.SSLError, socket.timeout, OSError) as e:
                        print(f"# TLS Handshake Aborted/Timed Out: {e}", flush=True)
                    except Exception as e:
                        print(f"# General TLS Error: {e}", flush=True)
                    finally:
                        target = tls_sock if tls_sock else connection
                        print("# Closing connection socket", flush=True)
                        try:
                            target.shutdown(socket.SHUT_RDWR)
                        except Exception:
                            pass
                        try:
                            target.close()
                        except Exception:
                            pass

            except Exception as e:
                print(f"# Connection handler exception: {e}", flush=True)
                try:
                    connection.close()
                except Exception:
                    pass

# Hardcoded server hello packet
server_hello = b'R\x00\x00\x00\n11.4.2-MariaDB\x00\xff\x01\x00\x00Nv\
*hQ;qK\x00\xfe\xff\x08\x02\x00\xff\x81\x15\x00\x00\x00\
\x00\x00\x00\x1d\x00\x00\x00`$-VIJyC!x[?\x00mysql_native_password\x00'


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        prog='tls_server',
        description='Simple TLS dummy test server')
    parser.add_argument('--host', help='Host address of TLS test server (Default 127.0.0.1)')
    parser.add_argument('--port', help='Port of TLS test server. (Default 50000)')

    args = parser.parse_args()

    if not (port := args.port):
        port = 50000
    if not (host := args.host):
        host = "127.0.0.1"
    server = TlsServer(host=host, port=int(port))
    print("# Starting tls_dummy_server", flush=True)
    server.run()
