#!/usr/bin/python

# poit is copyright 2009 by Yang Zhao <yang@yangman.ca>
# This file is distributed under terms of Apache License, Version 2.0
# For full text of the license, see http://www.apache.org/licenses/LICENSE-2.0
from __future__ import print_function

import cgi
import base64
import getpass
import hashlib
import logging
import logging.handlers
import os
import random
import re
import struct
import sys
import urllib
import pprint
from datetime import datetime
from optparse import OptionParser, OptionValueError

###########################################

##
# Check Python version, and do version-specific imports
py_version = sys.version_info[:2]
if py_version[0] == 3:
    import configparser
    import urllib.parse as urlparse
    from http import cookies
elif py_version[1] >= 6:
    import ConfigParser as configparser
    import urlparse
    from exceptions import IOError
    import Cookie as cookies
else:
    print('unsupported version of Python')
    sys.exit(1)

import openid
from openid.server import server
from openid.server.server import Server as OpenIDServer, CheckIDRequest, CheckAuthRequest
from openid.extensions.sreg import SRegRequest, SRegResponse
from openid.store.filestore import FileOpenIDStore
from openid.store.memstore import MemoryStore

POIT_VERSION = "0.1_alpha"
DEFAULT_CONFIG_FILES = [os.path.expanduser("~/.config/poit.conf"),
                        os.path.expanduser("~/.poit.conf"),
                        os.path.abspath("./poit.conf")]

#######################################
# Common functions

class BufferLogger(logging.Logger):
    '''Logger which outputs only when explicitly told to do so'''
    def __init__(self, name):
        logging.Logger.__init__(self, name)
        self._handler = logging.handlers.MemoryHandler(200)
        self._handler.shouldFlush = lambda x: False
        self._formatter = logging.Formatter("%(relativeCreated)04d %(levelname)s: %(message)s")
        self.addHandler(self._handler)

    def flush(self, file=sys.stdout):
        target = logging.StreamHandler(file)
        target.setFormatter(self._formatter)
        self._handler.setTarget(target)
        self._handler.flush()
        target.flush()
        self._handler.setTarget(None)

# Initialize a global Logger instance
logging.setLoggerClass(BufferLogger)
logger = logging.getLogger("buffered")
logger.setLevel(logging.DEBUG)

config = None

class ConfigManager():
    '''Manages configuration, profile and session information'''

    @classmethod
    def find_config_file(cls):
        file = None
        for f in DEFAULT_CONFIG_FILES:
            if not os.path.exists(f):
                logger.debug("`{0}' does not exist".format(f))
                continue
            file = f
            break
        return file

    def __init__(self, config_file):
        '''Constructor
        '''
        self.config_file = config_file
        self.session_dir = None
        self.endpoint = None
        self.debug = False

        self._keys_exist = False
        self._dirty = False
        self._parser = None

        self._parser = configparser.SafeConfigParser()
        self._parser.read(self.config_file)

        # Make sure all the sections exist
        for s in ["passphrase", "server", "ids", "ui", "security"]:
            try: self._parser.add_section(s)
            except configparser.DuplicateSectionError: pass

        # Sanity check values
        self._keys_exist = self._parser.has_option("passphrase", "md5") and \
                           self._parser.has_option("passphrase", "sha512")

        if not self._keys_exist:
            logger.warning("Passphrase not set")

        if self._parser.has_option("server", "endpoint"):
            self.endpoint = self._parser.get("server", "endpoint")

        if self._parser.has_option("session", "timeout"):
            self.timeout = self._parser.get("session", "timeout")
        else:
            self.timeout = 21600

        if self._parser.has_option("ui", "debug"):
            self.debug = self._parser.getboolean("ui", "debug")

        # Session folder
        try:
            self.session_dir = self._parser.get("server", "session_dir")
        except (configparser.NoSectionError, configparser.NoOptionError):
            self.session_dir = os.path.expanduser("~/.cache/poit/")

        # FIXME: on OpenID request, reply with error
        if not self.check_session_dir():
            raise IOError("Session directory not writable: " + self.session_dir)

    def __del__(self):
        self.save()

    def save(self):
        '''Saves configuration to file. Assumes config_file is set.'''
        if not self._dirty: return True
        logger.info("Saving configuration to " + self.config_file)
        with open(self.config_file, 'w') as f:
            self._parser.write(f)

    def set_endpoint(self, url, save_to_file=False):
        '''If url is empty, change attribute iff save_to_file is True'''
        if save_to_file:
            if url:
                self.endpoint = url
                self._parser.set("server", "endpoint", url)
            else:
                self._parser.remove_option("server", "endpoint")
            self._dirty = True
        else:
            self.endpoint = url

    def validate_passphrase(self, passphrase):
        if not (self._keys_exist and passphrase): return False
        def f(r, cipher):
            return r and \
                   (getattr(hashlib, cipher)(passphrase).digest() ==
                    base64.b64decode(self._parser.get("passphrase", cipher)))

        try:
            return reduce(f, ["md5", "sha512"])
        except TypeError:
            logger.warn("Malformed passphrase hash found")
            return False

    def set_passphrase(self, passphrase):
        for cipher in ["md5", "sha512"]:
            self._parser.set("passphrase", cipher,
                             base64.b64encode(getattr(hashlib, cipher)(passphrase).digest()))
        self._dirty = True

    # Identity management
    @staticmethod
    def _hash_identity(id):
        return "{0}_{1}".format(len(id), hashlib.md5(id).hexdigest()[0:16])

    def add_identity(self, id):
        # TODO: noop when already exist?
        self._parser.set("ids", ConfigManager._hash_identity(id), id)
        self._dirty = True

    def validate_id(self, id):
        try:
            return self._parser.get("ids", ConfigManager._hash_identity(id)) == id
        except (configparser.NoOptionError, configparser.NoSectionError):
            return False

    def get_passphrase_hash(self, hash):
        return self._parser.get("passphrase", hash)

    # Session Cookie methods
    # TODO: Implement a version using symmetric-key block cipher
    def _cookie_hash(self, salt, time):
        h = hashlib.sha512()
        # FIXME: check for hashes not being available?
        h.update(salt)
        h.update(time)
        h.update(self._parser.get("passphrase", "md5"))
        h.update(self._parser.get("passphrase", "sha512"))
        return h.digest()

    def validate_cookie_val(self, val):
        vals = val.split(":")
        try:
            salt = base64.b64decode(vals[0])
            time_str = vals[1]
            hash = base64.b64decode(vals[2])
        except (IndexError, TypeError):
            logger.warn("Malformed cookie value: " + val)
            return False

        now = datetime.utcnow()
        cookie_time = datetime.strptime(time_str, "%Y%m%d%H%M%S")

        diff = (now - cookie_time).seconds
        if diff < 0:
            logger.warn("Cookie time in the future")
            return False
        elif diff > self.timeout:
            logger.warn("Cookie timed out")
            return False

        return self._cookie_hash(salt, time_str) == hash

    def create_cookie_val(self):
        salt = struct.pack("34B", *(random.randint(0,255) for x in range(34)))
        time = datetime.utcnow().strftime("%Y%m%d%H%M%S")

        hash = self._cookie_hash(salt, time)

        val = "{0}:{1}:{2}".format(base64.b64encode(salt), time, base64.b64encode(hash))
        logger.debug("Cookie value: " + val)
        return val

    def set_security_policy(self, policy):
        # XXX: assumes input is valid value
        self._parser.set("security", "policy", policy)
        self._dirty = True

    def get_security_policy(self):
        if self._parser.has_option("security", "policy"):
            return self._parser.get("security", "policy")
        else:
            return "none"

    def force_https(self):
        return self.get_security_policy() == "https"

    def check_session_dir(self):
        '''Check that session storage directory exists has correct permissions'''
        # TODO: sanity check permissions when pre-existing
        if not os.path.exists(self.session_dir):
            try:
                os.makedirs(self.session_dir, 0x1C0) # 0x1C0 = 0o700
            except OSError as e:
                logger.error("Cannot create {dir}: {e}".format(self.session_dir, str(e)))
                return False
        return True

    def sreg_fields(self):
        return dict(self._parser.items("sreg")) if self._parser.has_section("sreg") else None

    
#######################################
# CGI functions

class CGIParser():
    '''Similar to cgi.FieldStorage, but specific to this script

    Instanciate once only, as sys.stdin is read.
     - OpenID fields are put into `openid' attribute.
     - POST and GET fields are kept in `post' and `get' attributes,
       respectively, with all OpenID fields filtered out
     '''
    def __init__(self):
        self.openid = dict()
        self.post = dict()
        self.get = dict()

        logger.debug("env:\n" + pprint.pformat(dict(os.environ)))

        # Process openid keys from GET fields iff it is not a POST request
        #  Section 4.1.2 of spec
        use_get = os.environ["REQUEST_METHOD"] != "POST"
        for (key, val) in urlparse.parse_qsl(os.environ["QUERY_STRING"], keep_blank_values = True):
            if key.startswith("openid."):
                if use_get: self.openid[key] = val
            else:
                self.get[key] = val
        logger.debug("GET fields:\n" + pprint.pformat(self.get))

        # FIXME: This needs to be more robust
        content_length = int(os.environ.get("CONTENT_LENGTH", 0))
        if content_length:
            content = sys.stdin.read(content_length)
            logger.debug("Content-Type: " + os.environ["CONTENT_TYPE"])
            logger.debug("data:\n" + content)
            if os.environ["CONTENT_TYPE"].startswith("application/x-www-form-urlencoded"):
                fields = urlparse.parse_qsl(content)
                for (key, val) in fields:
                    if key.startswith("openid."):
                        self.openid[key] = val
                    else:
                        self.post[key] = val
        logger.debug("POST fields:\n" + pprint.pformat(self.post))

        logger.debug("OpenID fields:\n" + pprint.pformat(self.openid))

    def self_uri(self, https=False):
        return "{scheme}://{server}{uri}".format(
                    scheme = ("https" if (os.environ.get("HTTPS", None) == "on" or https) else "http"),
                    server = os.environ["HTTP_HOST"],
                    uri = os.environ["SCRIPT_NAME"])


class Session:
    AUTHENTICATED = 0
    NO_SESSION = 1
    BAD_PASSPHRASE = 2

    def __init__(self, cgi_request):
        logger.debug("Initializing session object")
        self.cgi_request = cgi_request
        self._auth = Session.NO_SESSION
        try:
            self._cookie = cookies.SimpleCookie(os.environ["HTTP_COOKIE"])
        except cookies.CookieError as e:
            logger.warning("Bad cookie: " + str(e))
            self._cookie = None
        except KeyError:
            self._cookie = None

    def check_authentication(self):
        if not config: return

        if self._cookie and \
           config.validate_cookie_val(self._cookie["poit_session"].value):
            logger.info("Authenticated cookie session")
            self._auth = Session.AUTHENTICATED
        else:
            try:
                if config.validate_passphrase(self.cgi_request.post["passphrase"]):
                    logger.info("Authenticated using passphrase")
                    self._auth = Session.AUTHENTICATED
                else:
                    self._auth = Session.BAD_PASSPHRASE
            except KeyError:
                return False

    def is_secure(self):
        return os.environ.get("HTTPS", None) == "on"

    def auth_status(self):
        return self._auth

    def renew(self, timeout):
        logger.debug("Renew session for {0}s".format(timeout))
        if not self._cookie:
            self._cookie = cookies.SimpleCookie()

        endpoint = urlparse.urlparse(config.endpoint)

        self._cookie["poit_session"] = (config.create_cookie_val() if timeout else '')
        val = self._cookie["poit_session"]
        val["max-age"] = timeout
        val["domain"] = endpoint.netloc
        val["path"] = endpoint.path
        val["httponly"] = True
        if self.is_secure():
            val["secure"] = True

    def expire(self):
        self.renew(0)

    def get_cookie(self):
        return self._cookie

    def cookie_output(self):
        return self._cookie.output() if self._cookie else ""


class CGIResponse(list):
    """Wraps all HTTP and HTML output"""
    def __init__(self):
        self.session = None

        # OpenID request and response
        self.request = None
        self.response = None
        self.identity = None

        self.error = None
        self.cookie = None
        self.redirect_url = None
        self.headers = {}

    def set_content_type(self, type):
        if type:
            self.headers["Content-Type"] = type
        else:
            del self.headers["Content-Type"]

    def _append_form(self):
        form_action = config.endpoint
        if self.session.is_secure():
            # XXX: Preserve GET fields?
            form_action = re.sub("^http:", "https:", form_action)

        self.append('''<form action="{0}" method="post">
                <input type="password" name="passphrase" size="20" />
                <button type="submit">Authorize</button>'''.format(form_action))

        for (name, value) in self.session.cgi_request.openid.items():
            self.append('<input type="hidden" name="{0}" value="{1}" />'.format(name, value))

        self.append('</form>')
        if self.request:
            self.append('<a href="{0}">Reject</a>'.format(self.request.getCancelURL()))

    def _build_body(self):
        self.append("<html><head><title>poit</title></head><body>")

        if config:
            if self.session.auth_status() != Session.AUTHENTICATED:
                self._append_form()
        else:
            self.append("NO CONFIGURATION FILE")

        if config.debug:
            self.append("<pre>")
            self.append(logger.flush)
            self.append("</pre>")

        self.append("</body></html>")
        pass

    def output(self, file=sys.stdout):
        if self.redirect_url:
            print('Location:', self.redirect_url, file=file)
            print('', file=file)
        elif self.response:
            for (header, value) in self.response.headers.items():
                print("{0}: {1}".format(header, value), file=file)
            if self.cookie:
                print(self.cookie.output(), file=file)
            print('', file=file)
            print(self.response.body, file=file)
        else:
            self._build_body()
            
            for (header, value) in self.headers.items():
                print("{0}: {1}".format(header, value), file=file)
            if self.cookie:
                print(self.cookie.output(), file=file)
            print('', file=file)

            for data in self:
                if type(data) is str:
                    print(data, end='', file=file)
                else:
                    data(file)


def handle_sreg(request, response):
    """Handle any sreg data requests"""
    sreg_req = SRegRequest.fromOpenIDRequest(request)
    # Extract information if required
    if sreg_req.wereFieldsRequested():
        fields = config.sreg_fields()
        if not fields: return
        sreg_resp = SRegResponse.extractResponse(sreg_req, config.sreg_fields())
        sreg_resp.toMessage(response.fields)

def handle_openid(session, server, request, response):
    response.session = session
    oid_response = None

    if type(request) == CheckIDRequest:
        # Reject if identity is not accepable
        auth_stat = session.auth_status()
        if not config.validate_id(request.identity):
            logger.info("Invalid ID: " + request.identity)
            oid_response = False
        elif auth_stat == Session.AUTHENTICATED:
            oid_response = True
        elif request.immediate:
            logger.info("Rejected immediate_mode")
            oid_response = False
        elif auth_stat == Session.BAD_PASSPHRASE:
            logger.info("Bad passphrase")
            oid_response = False
        else:
            logger.info("Prompt for passphrase")
            response.set_content_type('text/html')
            response.request = request
            return response

        logger.info("Session validation: " + ("SUCCESS" if oid_response else "FAILURE"))

        if oid_response:
            session.renew(config.timeout)
            response.cookie = session.get_cookie()

        oid_response = request.answer(oid_response)
        handle_sreg(request, oid_response)

        logger.debug("Response:\n" + oid_response.encodeToKVForm())
    else:
        try:
            oid_response = server.handleRequest(request)
        except NotImplementedError as e:
            oid_response = server.OpenIDResponse(None)
            oid_response.fields['error'] = str(e)
            return

    # encode response
    oid_response = server.encodeResponse(oid_response)

    response.response = oid_response

    return response

def handle_normal(session, response):
    response.set_content_type('text/html')
    return response

def cgi_main():
    global config
    cgi_request = CGIParser()
    response = CGIResponse()

    # Load configuration
    config_file = ConfigManager.find_config_file()

    if not config_file:
        logger.error("No configuration file found")
        response.error = "No poit configuration file found"
        config = None
    else:
        try:
            config = ConfigManager(config_file)
        except configparser.ParsingError as e:
            logger.error('Unable to parse config file: {0}'.format(err))
            response.error = "Error parsing poit configuration file"

    if config:
        # Make sure an endpoint is set
        if not config.endpoint:
            config.set_endpoint(cgi_request.self_uri(https=config.force_https()))

        logger.debug("Endpoint: " + config.endpoint)
        ostore = FileOpenIDStore(config.session_dir)
        oserver = OpenIDServer(ostore, config.endpoint)
        logger.debug("Initialized server")
    else:
        # Stilll need to create a OpenIDServer to parse the request
        ostore = MemoryStore()
        oserver = OpenIDServer(ostore, "")
        logger.debug("Initialized dummy server")

    # Decode request
    try:
        request = oserver.decodeRequest(cgi_request.openid)
    except server.ProtocolError as err:
        logger.warn("Not an OpenID request: " + str(err))
        request = None

    session = Session(cgi_request)
    response.session = session

    # Redirect to HTTPS if required
    if (not session.is_secure()) and config.force_https() and \
            ((not request) or type(request) == CheckIDRequest):
        response.redirect_url = "{endpoint}?{fields}".format(
                    endpoint = re.sub("^http:", "https:", config.endpoint),
                    fields = urllib.urlencode(cgi_request.openid))
        response.output()
        return

    session.check_authentication()

    if request:
        handle_openid(session, oserver, request, response)
    else:
        handle_normal(session, response)

    ostore.cleanup()
    response.output()


#######################################
# Commandline mode functions

def setup_option_parser():
    parser = OptionParser(description="Modify poit configuration file",
                          usage="%prog [options] <config_file>",
                          version="poit {0}".format(POIT_VERSION))
    parser.add_option("-a", "--add-identity", action="append", dest="new_identity",
                      help="Add a new identity")
    parser.add_option("-p", "--passphrase", action="store_true", dest="passphrase",
                      help="Set a new passphrase")
    parser.add_option("--endpoint", dest="endpoint",
                      help='Set server endpoint URL; clear by setting to ""')
    parser.add_option("--security", dest="policy",
                      type="choice", choices=["none", "https"],
                      help="Set server's security policy: none or https")
    parser.add_option("-v", "--verbose", action="store_true", dest="debug",
                      help="Show debugging messages")

    return parser

def cli_main():
    global config
    parser = setup_option_parser()
    try:
        (options, args) = parser.parse_args()
    except OptionValueError:
        sys.exit(1)

    no_opts = True

    config_file = None

    def new_file_prompt(path):
        path = os.path.abspath(path)
        r = raw_input("Crate new configuration file at {0}? [Y/n]: ".format(path))
        r = r.lower() if r else "y"
        if r[0] == "y":
            config_file = DEFAULT_CONFIG_FILES[0]
            with open(config_file, 'w'): pass
            return True
        else:
            return False

    if args:
        config_file = args[0]
        if not os.path.exists(config_file):
            print("No configuration file at {0}".format(config_file))
            if not new_file_prompt(config_file):
                sys.exit(0)
    else:
        config_file = ConfigManager.find_config_file()
        if not config_file:
            config_file = DEFAULT_CONFIG_FILES[0]
            print("No configuration file found")
            if not new_file_prompt(config_file):
                sys.exit(0)

    print("Using {0}".format(config_file))
    config = ConfigManager(config_file)

    if options.endpoint is not None:
        no_opts = False
        config.set_endpoint(options.endpoint, save_to_file=True)
        if options.endpoint:
            print("Server endpoint is now: " + options.endpoint)
        else:
            print("Server endpoint unset")

    if options.new_identity:
        no_opts = False
        for id in options.new_identity:
            config.add_identity(id)
            print("Added new identity: " + id)

    if options.policy:
        no_opts = False
        config.set_security_policy(options.policy)
        print("Setting security policy to: {0}".format(options.policy))

    if options.passphrase:
        no_opts = False
        try:
            new_pass = getpass.getpass("New passphrase: ")
        except getpass.GetPassWarning:
            print("Your input may be echoed and your new passphrase compromised. Aborting.",
                  file=sys.stderr)
            sys.exit(1)

        if new_pass != getpass.getpass("Confirm new passphrase: "):
            print("Passphrases do not match")
            sys.exit(1)

        config.set_passphrase(new_pass)
        print("New passphrase set")

    if no_opts:
        parser.print_help()
    else:
        config.save()

    if options.debug:
        logger.flush()


#-----------------------------

if __name__ == '__main__':
    if 'REQUEST_METHOD' in os.environ:
        cgi_main()
    else:
        cli_main()
