#!/usr/bin/env python

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
DEFAULT_STYLESHEET = './poit.css'

CONFIG_REALM_PREFIX = 'realm|'

############################
# HTML

HTML_HEADER = '''<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html><head>
  <title>poit OpenID Server</title>
  <link rel="stylesheet" href="{stylesheet}" type="text/css" />
</head><body>
'''

HTML_FORM_START = '<form action="{endpoint}" method="post" id="form_box">'
HTML_IDENTITY = '<p id="identity">{identity}</p>'
HTML_REALM = '<p id="realm_box">Authenticate to<br/><span id="realm_str">{realm}</span></p>'
HTML_FORM_PASSPHRASE = '''<p id="passphrase_box">
<label id="passphrase_label">Passphrase<br/>
<input type="password" id="passphrase_input" name="poit.passphrase" size="20" /></label>
</p>'''
HTML_FORM_HIDDEN = '<input type="hidden" name="{name}" value="{value}"/>'
HTML_BUTTONS_START = '<div id="buttons">'
HTML_BUTTON_AUTHENTICATE = '<button type="submit" name="poit.action" value="authenticate">Authenticate</button>'
HTML_BUTTON_CANCEL = '<button type="submit" name="poit.action" value="cancel">Cancel</button>'
HTML_BUTTON_LOGOUT = '<button type="submit" name="poit.action" value="expire">Expire Session</button>'
HTML_BUTTONS_END = '</div>'
HTML_FORM_END = '</form>'

HTML_FORM_ID_SELECT_START = '<p id="identity"><select name="poit.id" size="1">'
HTML_FORM_ID_SELECT_OPTION = '<option>{identity}</option>'
HTML_FORM_ID_SELECT_END = '</select></p>'

HTML_CB_REMEMBER_BASE = '<label><input type="checkbox" name="poit.allow_immediate"{0}/>Remember approval</label>'
HTML_CB_REMEMBER = HTML_CB_REMEMBER_BASE.format('')
HTML_CB_REMEMBER_CHECKED = HTML_CB_REMEMBER_BASE.format(' checked="checked"')

HTML_ERROR_MESSAGE = '<p id="error">{message}</p>'

HTML_AUTHENTICATED_INFO = '''<p class="info">You are already logged in to poit.</p>
<p class="info">You can now authenticate to OpenID-supporting sites without being asked for your
passphrase again.</p>'''

HTML_FOOTER = '''<p id="version">poit {version}</p>
<script type="text/javascript">
try{{document.getElementById('passphrase_input').focus();}}catch(e){{}}
</script>
</body></html>'''

HTML_DEBUG_START = '<pre id="debug">'
HTML_DEBUG_END = '</pre>'

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

    def html_mode(self):
        self._formatter.format = lambda r: cgi.escape(logging.Formatter.format(self._formatter, r))

# Initialize a global Logger instance
logging.setLoggerClass(BufferLogger)
logger = logging.getLogger("buffered")
logger.setLevel(logging.DEBUG)

config = None

class OpenIDRealm():
    def __init__(self, url, allow_immediate=False):
        self.url = url
        self.allow_immediate = allow_immediate

    def apply_action(self, action):
        """Apply PoitAction realm profile changes"""
        changed = False
        if action.allow_immediate:
            changed = (not self.allow_immediate)
            self.allow_immediate = True

        return changed


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

    def save(self):
        '''Saves configuration to file. Assumes config_file is set.'''
        if not self._dirty:
            logger.debug("No config file change")
            return True
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

    def get_identities(self):
        return [x[1] for x in self._parser.items("ids")]

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

    def get_stylesheet(self):
        try:
            return self._parser.get('ui', 'stylesheet')
        except (configparser.NoOptionError, configparser.NoSectionError):
            return DEFAULT_STYLESHEET

    def sreg_fields(self):
        return dict(self._parser.items("sreg")) if self._parser.has_section("sreg") else None

    # Realm profiles
    def get_realm(self, name):
        section = CONFIG_REALM_PREFIX + name
        if not self._parser.has_section(section):
            return None

        realm = OpenIDRealm(name)
        try:
            realm.allow_immediate = self._parser.getboolean(section, 'immediate')
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            realm.allow_immediate = False

        return realm

    def save_realm(self, realm):
        section = CONFIG_REALM_PREFIX + realm.url
        if not self._parser.has_section(section):
            self._parser.add_section(section)

        self._parser.set(section, 'immediate', str(realm.allow_immediate))
        self._dirty = True

    
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
            if os.environ["CONTENT_TYPE"].startswith("application/x-www-form-urlencoded"):
                fields = urlparse.parse_qsl(content)
                for (key, val) in fields:
                    if key.startswith("openid."):
                        self.openid[key] = val
                    else:
                        self.post[key] = val

        if 'poit.passphrase' in self.post:
            p = self.post.copy()
            p['poit.passphrase'] = "**REMOVED**"
            logger.debug("POST fields:\n" + pprint.pformat(p))
        else:
            logger.debug("POST fields:\n" + pprint.pformat(self.post))
        logger.debug("OpenID fields:\n" + pprint.pformat(self.openid))

    def self_uri(self, https=False):
        return "{scheme}://{server}{uri}".format(
                    scheme = ("https" if (os.environ.get("HTTPS", None) == "on" or https) else "http"),
                    server = os.environ["HTTP_HOST"],
                    uri = os.environ["SCRIPT_NAME"])


class Session:
    def __init__(self, cgi_request):
        logger.debug("Initializing session object")
        self.cgi_request = cgi_request
        self.authenticated = False
        try:
            self._cookie = cookies.SimpleCookie(os.environ["HTTP_COOKIE"])
        except cookies.CookieError as e:
            logger.warning("Bad cookie: " + str(e))
            self._cookie = None
        except KeyError:
            self._cookie = None

        if self._cookie:
            # If cookie is found, check then purge it
            try:
                session = self._cookie['poit_session']
            except KeyError:
                pass
            else:
                if config.validate_cookie_val(session.value):
                    logger.info("Authenticated cookie session")
                    self.authenticated = True

            self._cookie = None

    def is_secure(self):
        return os.environ.get("HTTPS", None) == "on"

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

    def cookie_output(self):
        return self._cookie.output() if self._cookie else ""


class PoitAction:
    def __init__(self):
        self.type = None
        self.identity = None
        self.error = None
        self.allow_immediate = False

    def __str__(self):
        return str({'type': self.type, 'identity': self.identity})

    @classmethod
    def from_request(cls, request, authenticated=False):
        if 'poit.action' not in request:
            return None

        command = request['poit.action']
        action = PoitAction()

        if command == 'authenticate':
            if authenticated:
                action.type = 'authenticate'
            elif 'poit.passphrase' in request and \
                    config.validate_passphrase(request['poit.passphrase']):
                logger.info("Authenticated using passphrase")
                action.type = 'authenticate'
            else:
                action.error = "Incorrect Passphrase"
                action.type = 'ask_again'

            action.identity = request.get('poit.id', None)
            action.allow_immediate = (request.get('poit.allow_immediate', None) == 'on')

        elif command in ['cancel', 'expire']:
            action.type = command

        return action


class CGIResponse(list):
    """Wraps all HTTP and HTML output"""
    def __init__(self):
        self.type = None

        # OpenID request and response
        self.response = None
        self.identity = None
        self.realm = None

        self.error = None
        self.redirect_url = None
        self.headers = {}

    def _build_body(self, session):
        self.append(HTML_HEADER.format(stylesheet=config.get_stylesheet()))

        form_action = config.endpoint
        if session.is_secure():
            form_action = re.sub("^http:", "https:", form_action)

        self.append(HTML_FORM_START.format(endpoint=form_action))

        # Identity list
        if self.type == 'openid_authenticate':
            # if identity is False but not None, then have user select one
            if (self.identity is not None) and (not self.identity):
                ids = config.get_identities()
                if len(ids) == 1:
                    self.identity = ids[0]
                    self.append(HTML_IDENTITY.format(identity=self.identity))
                    self.append(HTML_FORM_HIDDEN.format(name='poit.id', value=self.identity))
                else:
                    self.append(HTML_FORM_ID_SELECT_START)
                    for id in ids:
                        self.append(HTML_FORM_ID_SELECT_OPTION.format(identity=id))
                    self.append(HTML_FORM_ID_SELECT_END)
            else:
                self.append(HTML_IDENTITY.format(identity=self.identity))

            self.append(HTML_REALM.format(realm=self.realm))
        elif self.type == 'session_info':
            ids = config.get_identities()
            if len(ids) == 1:
                self.append(HTML_IDENTITY.format(identity=ids[0]))
            else:
                self.append(HTML_IDENTITY.format(identity="{0} identities available".format(len(ids))))

        if self.type == 'session_info':
            self.append(HTML_AUTHENTICATED_INFO)

        # Error message
        if self.error:
            self.append(HTML_ERROR_MESSAGE.format(message=self.error))

        # Input fields
        if self.type != 'error':
            if not session.authenticated:
                self.append(HTML_FORM_PASSPHRASE)

            if self.type in ['openid_authenticate']:
                self.append(HTML_CB_REMEMBER)

            self.append(HTML_BUTTONS_START)
            if self.type in ['openid_authenticate', 'plain_authenticate']:
                self.append(HTML_BUTTON_AUTHENTICATE)

            if self.type == 'openid_authenticate':
                self.append(HTML_BUTTON_CANCEL)
            elif self.type == 'session_info':
                self.append(HTML_BUTTON_LOGOUT)
            self.append(HTML_BUTTONS_END)

            # OpenID fields
            for (name, value) in session.cgi_request.openid.items():
                self.append(HTML_FORM_HIDDEN.format(name=name, value=value))

        self.append(HTML_FORM_END)

        # Debug log
        if config and config.debug:
            self.append(HTML_DEBUG_START)
            self.append(logger.flush)
            if self.redirect_url:
                self.append('Redirect: <a href="{0}">{0}</a>'.format(self.redirect_url))
            self.append(HTML_DEBUG_END)

        self.append(HTML_FOOTER.format(version=POIT_VERSION))
        pass

    def output(self, session, file=sys.stdout):
        if self.type == 'no_config':
            print('status: 500 poit: No configuration file found', file=file)
            print('', file=file)
            return

        # Prepare output data
        if config.debug:
            if self.response:
                logger.debug("OpenID response headers:\n" + pprint.pformat(self.response.headers))
                if 'location' in self.response.headers:
                    self.redirect_url = self.response.headers['location']

            logger.debug(session.cookie_output())
            self._build_body(session)
            headers = {}
            body = self
        else:
            if self.redirect_url:
                headers = {'Location': self.redirect_url}
                body = []
            elif self.response:
                headers = self.response.headers
                body = [self.response.body]
            else:
                self._build_body(session)
                headers = self.headers
                body = self

        # Output
        print('Content-Type: text/html', file=file)
        for (header, value) in headers.items():
            print("{0}: {1}".format(header, value), file=file)
        cookie = session.cookie_output()
        if cookie: print(cookie, file=file)
        print('', file=file)

        for data in body:
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

def handle_openid(session, server, request, response, action):
    oid_response = None

    if type(request) == CheckIDRequest:
        response.identity = request.identity
        response.realm = request.trust_root

        answer_id = None
        oid_response = False

        if request.immediate:
            if session.authenticated:
                realm = config.get_realm(request.trust_root)

                if request.idSelect():
                    ids = config.get_identities()
                    if len(ids) == 1:
                        answer_id = config.get_identities()[0]
                        logger.info("ACCEPT (immediate): as '{0}'".format(answer_id))
                        oid_response = True
                    else:
                        logger.info("REJECT (immediate): need identity selection")
                elif realm and realm.allow_immediate:
                    logger.info("ACCEPT (immediate)")
                    oid_response = True
                else:
                    logger.info("REJECT (immediate): not allowed")
            else:
                logger.info("REJECT (immediate): no session")
        elif session.authenticated:
            if request.idSelect():
                if action:
                    answer_id = action.identity
                else:
                    logger.info("PROMPT: Need identity selection")
                    response.type = 'openid_authenticate'
                    return response

            if action:
                id = answer_id if answer_id else request.identity
                if config.validate_id(id):
                    oid_response = True

                    # Handle realm profile changes
                    realm = config.get_realm(request.trust_root)
                    if not realm: realm = OpenIDRealm(request.trust_root)
                    if realm.apply_action(action):
                        config.save_realm(realm)
                else:
                    logger.info("REJECT: Invalid ID: {0}".format(id))
            else:
                logger.info("PROMPT: checkid_setup mode")
                response.type = 'openid_authenticate'
                return response
        else:
            if not action or action.type == 'ask_again':
                logger.info("PROMPT: {0} passphrase".format("Incorrect" if action else "Need"))
                response.type = 'openid_authenticate'
                if request.idSelect():
                    logger.info("identity_select mode")
                    response.identity = False
                if action:
                    response.error = action.error
                return response
            elif action.type == 'cancel':
                logger.info("REJECT: Denied by user")
            else:
                logger.warn("REJECT: Unexpected action: {0}".format(action.type))

        if oid_response:
            session.renew(config.timeout)

        oid_response = request.answer(oid_response, identity=answer_id)
        handle_sreg(request, oid_response)

        logger.debug("Response:\n" + oid_response.encodeToKVForm())
    else:
        try:
            oid_response = server.handleRequest(request)
        except NotImplementedError as e:
            oid_response = server.OpenIDResponse(None)
            oid_response.fields['error'] = str(e)
            return

    response.response = server.encodeResponse(oid_response)
    return response

def handle_normal(session, response, action):
    if action:
        if action.type == 'ask_again':
            response.error = action.error
        elif action.type == 'expire':
            session.authenticated = False
            session.expire()

    if session.authenticated:
        session.renew(config.timeout)
        response.type = 'session_info'
    else:
        response.type = 'plain_authenticate'
    return response

def cgi_main():
    logger.html_mode()
    global config
    cgi_request = CGIParser()
    response = CGIResponse()

    # Load configuration
    config_file = ConfigManager.find_config_file()

    if not config_file:
        logger.error("No configuration file found")
        response.type = 'no_config'
        response.output(None)
        return
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

    # Redirect to HTTPS if required
    if (not session.is_secure()) and config.force_https() and \
            ((not request) or type(request) == CheckIDRequest):
        response.redirect_url = "{endpoint}?{fields}".format(
                    endpoint = re.sub("^http:", "https:", config.endpoint),
                    fields = urllib.urlencode(cgi_request.openid))
        response.output(session)
        return

    action = PoitAction.from_request(cgi_request.post)

    logger.debug("Action: " + str(action))

    if action and action.type == 'authenticate' and not session.authenticated:
        session.authenticated = True

    if request:
        handle_openid(session, oserver, request, response, action)
    else:
        handle_normal(session, response, action)

    config.save()
    ostore.cleanup()
    response.output(session)


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
