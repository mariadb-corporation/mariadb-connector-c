import socket
import ssl
import argparse
from ast import literal_eval
# from OpenSSL import crypto, SSL
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, UTC
import os

class TlsServer():

    def __init__(self, *args, **kwargs):
        self.host= kwargs.pop("host", "127.0.0.1")
        self.port= kwargs.pop("port", 50000)
        self.server= None
        self.context= None
        self.end= False

        try:
            self.server= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.host, self.port))
            print("# tls dummy_server started: ", self.host, self.port)
            self.server.listen()
        except Exception as e:
            print("Couldn't start tls_server")
            print(e)

    def check_server(self):
        if not self.server:
            raise Exception("Server not started")


    def send_server_hello(self, conn):
        self.check_server()
        try:
            conn.sendall(server_hello)
        except Exception as e:
            print("Couldn't send server_hello")
            print(e)
            return 0
        return 1

    def generate_cert(self,
                  create_new=False,
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
                  validityStartInSeconds=0,
                  validityEndInSeconds=10*365*24*60*60,
                  KEY_FILE="privkey.pem",
                  CRL_FILE="selfsigned.crl",
                  CERT_FILE="selfsigned.pem"):

        self.key_file = KEY_FILE
        self.cert_file = CERT_FILE
        self.crl_file = CRL_FILE

        if not create_new:
            return 1

        try:
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
            )

            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, countryName),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,
                                   stateOrProvinceName),
                x509.NameAttribute(NameOID.LOCALITY_NAME,
                                   localityName),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                                   organizationName),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                                   organizationUnitName),
                x509.NameAttribute(NameOID.COMMON_NAME,
                                   commonName),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS,
                                   emailAddress),
            ])

            now = datetime.now(UTC)

            cert_builder = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(serialNumber)
                .not_valid_before(
                    now + timedelta(seconds=validityStartInSeconds)
                )
                .not_valid_after(
                    now + timedelta(seconds=validityEndInSeconds)
                )
            )

            if SAN:
                san_entries = []

                for item in SAN.split(","):
                    item = item.strip()

                    if item.startswith("DNS:"):
                        san_entries.append(
                            x509.DNSName(item[4:])
                        )
                    elif item.startswith("IP:"):
                        import ipaddress
                        san_entries.append(
                            x509.IPAddress(
                                ipaddress.ip_address(item[3:])
                            )
                        )

                if san_entries:
                    cert_builder = cert_builder.add_extension(
                        x509.SubjectAlternativeName(san_entries),
                        critical=False,
                    )

            cert = cert_builder.sign(
                private_key=key,
                algorithm=hashes.SHA512(),
            )

            with open(CERT_FILE, "wb") as f:
                f.write(
                    cert.public_bytes(
                        serialization.Encoding.PEM
                    )
                )

            with open(KEY_FILE, "wb") as f:
                f.write(
                    key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )

            return 1

        except Exception as e:
            print(e)
            return 0

    def set_tls_context(self, reply):
        kwargs= {}
        if len(reply) > 0:
            cmds= reply.decode()
            kwargs= dict((k, literal_eval(v)) for k, v in (pair.split('=') for pair in cmds.split()))
        print("# command: ", kwargs)
        if self.generate_cert(**kwargs):
            print("# loading certs", self.cert_file, self.key_file)
            self.context= ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.load_cert_chain(self.cert_file, self.key_file)
            return 1
        return 0


    def accept(self):
        self.check_server()
        conn, addr= self.server.accept()
        return (conn, addr)

    def run(self):
        while not self.end:
            connection, address= self.accept()
            print("# new connection")
            self.send_server_hello(connection)
            reply= connection.recv(4096)
            if reply[:4] == b'CMD:':
                if self.set_tls_context(reply[4:]):
                    connection.sendall(b'OK')
            elif reply[:4] == b'QUIT':
                print("# exiting tls_dummy_server")
                try:
                    connection.close()
                except:
                    pass
                return
            else:
                try:
                    tls_sock= self.context.wrap_socket(connection, server_side=True)
                except Exception as e:
                    print("error occured")
                    print(e)
                    connection.close()
            connection.close()

# Hardcoded server hello packet (captured from MariaDB Server 11.4.2)
server_hello = b'R\x00\x00\x00\n11.4.2-MariaDB\x00\xff\x01\x00\x00Nv\
*hQ;qK\x00\xfe\xff\x08\x02\x00\xff\x81\x15\x00\x00\x00\
\x00\x00\x00\x1d\x00\x00\x00`$-VIJyC!x[?\x00mysql_native_password\x00'


if __name__ == '__main__':

    parser= argparse.ArgumentParser(
                       prog='tls_server',
                       description='Simple TLS dummy test server')
    parser.add_argument('--host', help='Hostaddress of TLS test server (Default 127.0.0.1)')
    parser.add_argument('--port', help='Port of TLS test server. (Default 50000)')

    args= parser.parse_args()

    if not (port := args.port):
        port= 50000;
    if not (host := args.host):
        host= "127.0.0.1"
    server= TlsServer(host=host, port=int(port))
    print("# Starting tls_dummy_server")
    server.run()
