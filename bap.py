#!/usr/bin/env python

#
# bap - http Basic Authentication honeyPot
#
# A webservice honeypot that logs HTTP basic authentication credentials
# in a "parser friendly format"(tm).
#

import os
import logging.handlers
import BaseHTTPServer
import base64

# Config
HTTP_ADDR = ''
HTTP_PORT = 8080


class BapRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    # Log setup
    formatter = logging.Formatter('[%(asctime)s] %(message)s')
    bapdir = os.path.dirname(__file__)

    # pot.log
    potlogger = logging.getLogger('pot')
    hdlr = logging.handlers.WatchedFileHandler(
        os.path.join(bapdir, 'pot.log'),
        'a', encoding=None, delay=False)
    hdlr.setFormatter(formatter)
    potlogger.addHandler(hdlr)
    potlogger.setLevel(logging.INFO)

    # access.log
    accesslogger = logging.getLogger('access')
    hdlr = logging.handlers.WatchedFileHandler(
        os.path.join(bapdir, 'access.log'),
        'a', encoding=None, delay=False)
    hdlr.setFormatter(formatter)
    accesslogger.addHandler(hdlr)
    accesslogger.setLevel(logging.INFO)

    # error.log
    errorlogger = logging.getLogger('error')
    hdlr = logging.handlers.WatchedFileHandler(
        os.path.join(bapdir, 'error.log'),
        'a', encoding=None, delay=False)
    hdlr.setFormatter(formatter)
    errorlogger.addHandler(hdlr)
    errorlogger.setLevel(logging.INFO)

    # Get client source port
    def srcport_string(self):
        host, port = self.client_address[:2]
        return port

    #
    # Override BaseHTTPServer
    #

    # Set server header
    server_version = 'Admin Console/1.0'
    sys_version = ''

    # Hide error response body
    error_message_format = ''

    # Change log format
    def log_request(self, code='-', size='-'):
        self.log_message(
            '"%s" %s "%s"',
            self.requestline.replace('"', '\\"'),
            str(code),
            self.headers.getheader('User-Agent', '').replace('"', '\\"'))

    # Log messages to access.log instead of stderr
    def log_message(self, format, *args):
        self.accesslogger.info(
            '%s:%s %s',
            self.address_string(),
            self.srcport_string(),
            format%args)

    # Log errors to error.log instead of calling log_message()
    def log_error(self, format, *args):
        self.errorlogger.info(
            '%s:%s %s',
            self.address_string(),
            self.srcport_string(),
            format%args)

    # Skip name resolving
    def address_string(self):
        host, port = self.client_address[:2]
        return host

    #
    # Request handling
    #

    # Handle requests in do_HEAD()
    def do_HEAD(self):
        # Always send 401 response
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="ADMIN"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        # Decode and log credentials, if any.
        authstring = self.headers.getheader('Authorization', None)
        if authstring != None:
            authparts = authstring.split()
            if len(authparts) == 2 and authparts[0] == 'Basic':
                try:
                    authdecoded = base64.b64decode(authparts[1])
                except TypeError, e:
                    self.errorlogger.info(
                        '%s:%s DecodeFailure %s',
                        self.address_string(),
                        self.srcport_string(),
                        authparts[1])
                else:
                    self.potlogger.info(
                        '%s:%s Basic %s',
                        self.address_string(),
                        self.srcport_string(),
                        authdecoded)

    # GET = HEAD
    def do_GET(self):
        self.do_HEAD()


# Main
def main():
    httpd = BaseHTTPServer.HTTPServer(
        (HTTP_ADDR, HTTP_PORT), BapRequestHandler)
    print "Starting service on %s:%s" % (HTTP_ADDR, HTTP_PORT)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print "Service stopped"

if __name__ == '__main__':
    main()
