#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import threading
import sys
import subprocess
import logging
import os
import yaml
import optparse

class InvalidCertificateTypeException(Exception):
    pass

class UnreadableCertificateException(Exception):
    pass

class InvalidFileFormatException(Exception):
    pass

def locate(file):
    #Find the path for fping
    for path in os.environ["PATH"].split(os.pathsep):
        if os.path.exists(os.path.join(path, file)):
                return os.path.join(path, file)
    return "{}".format(file)

def parse_config(conf):
    with open(conf, 'r') as stream:
        try:
            config = yaml.safe_load(stream)
            if not isinstance(config, list) or len(config) < 1:
                raise InvalidFileFormatException("File format has to be a list")
            if not all('type' in c and 'path' in c for c in config):
                raise InvalidFileFormatException("File list has to contains {type: string, path: string} objects")
            for c in config:
                if c['type'] not in ["x509", "crl"]:
                    raise InvalidCertificateTypeException("{} certificate type is not handled (x509|crl)".format(c['type']))
                if not open(c['path'], "r").readable():
                    raise InvalidCertificateTypeException("{} certificate is not readable".format(c['path']))
            return config
        except yaml.YAMLError as exc:
            logger.error(exc)

def check_cert(cert_type, cert_path):
    openssl_command = "{} {} -in {} -text -noout".format(openssl, cert_type, cert_path)
    if cert_type == "x509":
        openssl_command += " | grep -i 'Not After' | sed 's/.*After : //'"
    elif cert_type == "crl":
        openssl_command += " | grep -i 'next update' | sed 's/.*Update: //'"

    date_command = "date +%s -d \"$({})\"".format(openssl_command)

    #Log the actual date_command for debug purpose
    logger.info(date_command)
    #Execute the date_command
    date = subprocess.Popen(date_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)\
            .communicate()[0].decode("utf-8")
    #Prepare the output
    output = "probe_{}_earliest_cert_expiry {}".format(cert_type, date)
    return output

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

class GetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        message = "\n".join(check_cert(c['type'], c['path']) for c in config)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(message.encode())
        return

if __name__ == '__main__':
    parser = optparse.OptionParser("usage: openssl-cert-exporter [-p PORT -c CONFIG]")
    parser.add_option("-c", "--config", dest="config",
                      default="./config.yml", type="string",
                      help="Path to the config path. Default value: ./config.yml")
    parser.add_option("-p", "--port", dest="port", default=9997,
            type="int", help="Port to run on. Default value: 9997")

    (options, args) = parser.parse_args()
    config_file = options.config
    port = options.port

    global config
    config = parse_config(config_file)
    #Locate the path of openssl
    global openssl
    openssl = locate("openssl")
    logger = logging.getLogger()
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    #Check if there is a special port configured
    if len(sys.argv) >= 3:
        port = int(sys.argv[2])
    else:
        port = 9997
    logger.info('Starting server port {}, use <Ctrl-C> to stop'.format(port))
    server = ThreadedHTTPServer(('0.0.0.0', port), GetHandler)
    server.serve_forever()

