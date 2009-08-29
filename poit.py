#!/usr/bin/python

import cgi
import exceptions
import logging
import logging.handlers
import os
import re
import sys
import pprint

import cgitb; cgitb.enable()

###########################################

##
# Check Python version, and do version-specific imports
py_version = sys.version_info[:2]
if py_version[0] == 3:
    import configparser
    from http.cookies import SimpleCookie
elif py_version[1] >= 6:
    import ConfigParser as configparser
    from Cookie import SimpleCookie
else:
    print('unsupported version of Python')
    sys.exit(1)

import openid
from openid.server import server
from openid.server.server import Server as OpenIDServer, CheckIDRequest, CheckAuthRequest
from openid.extensions.sreg import SRegRequest, SRegResponse
from openid.store.filestore import FileOpenIDStore

auth_key = None
query = {}
cookie = None

#######################################
# Common functions

def init_logger():
    '''
    Initializes the root logger to log to memory

    The logs are dumped as required for debugging purposes
    '''
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    mem_hdlr = logging.handlers.MemoryHandler(200)
    mem_hdlr.shouldFlush = lambda x: False
    stream_hdlr = logging.StreamHandler(sys.stdout)
    stream_hdlr.setFormatter(logging.Formatter('%(relativeCreated)04d %(levelname)s: %(message)s'))

    mem_hdlr.setTarget(stream_hdlr)
    logger.addHandler(mem_hdlr)
    return logger


class ConfigManager():
    '''Manages configuration, profile and session information

    User-controlled configurations are stored in a poit.cfg file, looked for in
    ~/.poit and script directory, in that order.
    '''

    def __init__(self, config_mode=False):
        '''Constructor

        If config_mode is true, do not throw exceptions when file does not exist
        '''
        self.cfgfile = None
        self.session_dir = None

        self._keys_exist = False
        self._dirty = False
        self._parser = None

        # Find and load configuration file
        for dir in [os.path.expanduser('~/.poit'), '.']:
            f = dir + "/poit.config"
            if not os.path.exists(f):
                logging.debug("`{0}' does not exist".format(f))
                continue

            self.cfgfile = f
            break

        if not (self.cfgfile or config_mode) :
            logging.error("Configuration file not found")
            raise exceptions.IOError("File not found")

        self._parser = configparser.SafeConfigParser()
        self._parser.read(self.cfgfile)

        # Sanity check values
        self._keys_exist = self._parser.has_option("passphrase", "md5") and \
                           self._parser.has_option("passphrase", "sha512")

        if not self._keys_exist:
            logging.warning("Passphrase not set")
        if not self._parser.has_section("ids"):
            self._parser.add_section("ids")

        # Session folder
        try:
            self.session_dir = self._parser.get("session", "store_dir")
        except (configparser.NoSectionError, configparser.NoOptionError):
            self.session_dir = os.path.expanduser("~/.cache/poit/")

        if not config_mode and not self.check_session_dir():
            raise exceptions.IOError("Session directory not writable: " + self.session_dir)

    def __del__(self):
        self.save()

    def save(self):
        '''Saves configuration to file. Assumes cfgfile is set.'''
        if not self._dirty: return True
        logging.info("Saving configuration to " + self.cfgfile)
        self._parser.write(open(cfgfile, 'w'))

    def validate_passphrase(self, passphrase):
        if not (self._keys_exist and passphrase): return False
        if hashlib.md5(passphrase).hexdigest() != self._parser.get("passphrase", "md5"): return False
        if hashlib.sha512(passphrase).hexdigest() != self._parser.get("passphrase", "sha512"): return False
        return True

    def validate_id(self, id):
        return (re.sub(r'^http[s]?://(.*[^/])[/]?$', r'\1', id, 1) in self._parser.options('ids'))

    def get_passphrase_hash(self, hash):
        return self._parser.get("passphrase", hash)

    def force_https(self):
        return self._parser.has_option("security", "force_https") and \
               self._parser.getboolean("security", "force_https")

    def check_session_dir(self):
        '''Check that session storage directory exists has correct permissions'''
        # TODO: sanity check permissions when pre-existing
        if not os.path.exists(self.session_dir):
            try:
                os.makedirs(self.session_dir, 0700)
            except OSError as e:
                logging.error("Cannot create {dir}: {e}".format(self.session_dir, str(e)))
                return False
        return True


    
#######################################
# CGI functions

import hashlib
import fileinput


class OpenIDSessionCookie(SimpleCookie):
    def set_timeout(self, timeout=3600):
        '''Set expiration of cookie timeout seconds into the future
        If 0, expire this cookie
        '''
        for o in self.values():
            o['expires'] = timeout
            o['secure'] = True
            o['path'] = '/openid'
        return self

    def expire(self): return self.set_timeout(0)
    def renew(self): return self.set_timeout()

    def __set_secure(self, opt, val, timeout=3600):
        self[opt] = val
        self[opt]['expires'] = timeout
        self[opt]['secure'] = True
        self[opt]['path'] = '/openid'

    def set_hash(self, name, value):
        self.__set_secure(name, value)


class OpenIDKey:
    '''OpenID authentication keys stored locally'''

    def __init__(self, cfg):
        self.cfg = cfg

    def validate(self, key):
        '''Validate a passphrase or cookie'''
        if type(key) == str:
            return self.cfg.validate_passphrase(key)

        elif type(key) == OpenIDSessionCookie:
            try:
                h = hashlib.sha1()
                h.update(self.md5)
                h.update(key['openid_1'].value)
                h.update(self.sha512)

                return h.hexdigest() == key['openid_2'].value
            except KeyError:
                return False

        else:
            return False

    def cookie(self):
        '''Make a new session cookie'''
        import random
        salt = ''.join([random.choice('0123456789abcdef') for x in range(40)])
        h = hashlib.sha1()
        h.update(self.cfg.get_passphrase_hash("md5"))
        h.update(salt)
        h.update(self.cfg.get_passphrase_hash("sha512"))
        key = h.hexdigest()

        cookie = OpenIDSessionCookie()
        cookie.set_hash('openid_1', salt)
        cookie.set_hash('openid_2', key)

        return cookie
    

def check_passphrase(cfg, passphrase):
    '''Ask for and validate passphrase'''
    # Login attempt
    if passphrase:
        # Check hashes
        if not auth_key.validate(passphrase):
            return False

        # Set cookie
        global cookie
        cookie = auth_key.cookie()
        return True

    else:
        import re
        if "REDIRECT_URL" in os.environ:
            redirect = os.environ['REDIRECT_URL']
            if cfg.force_https():
                redirect = re.sub(r'^http:', 'https:', os.environ['REDIRECT_URL'])
        else:
            redirect = ("https" if os.environ.get("HTTPS", None) == "on" else "http") + \
                       "://" + os.environ["HTTP_HOST"] + os.environ["SCRIPT_NAME"]

        print("Content-Type: text/html\n")
        print('''<html><head><title>OpenID authenticate</title></head>
            <body>
            <form action="{0}" method="post">
                <input type="password" name="passphrase" size="20" />
                <button type="submit">Authorize</button>'''.format(redirect))

        for p in query.items():
            print('<input type="hidden" name="%s" value="%s" />' % p)

        print('</form>')
        print('<a href="%s">Reject</a>' % (request.getCancelURL(),))
        print('<pre>')
        logging.shutdown()
        print('</pre></body></html>')
        sys.exit()

    return False


def check_session():
    '''Check whether or not a session cookie has already been made'''
    if not auth_key.validate(cookie):
        return False

    # Update cookie's expiration time
    cookie.renew()
    return True

def handle_login(request, passphrase):
    pass

def handle_nonopenid(query, passphrase=None):
    """Handle non-OpenID requests"""
    print('Content-Type: text/plain\n')
    print(os.environ)
    sys.exit()


def handle_sreg(request, response):
    """Handle any sreg data requests"""
    sreg_req = SRegRequest.fromOpenIDRequest(request)
    # Extract information if required
    if sreg_req.required or sreg_req.required:
        import re
        f = fileinput.FileInput(sreg_file)
        p = re.compile('^(\w+):\s*(\S+)')
        user_data = {}
        for line in fileinput.input():
            m = p.match(line)
            if m: user_data[m.group(1)] = m.group(2)

        # Extract the sreg data actually requested
        #data = dict([(x, user_data[x]) for x in sreg_req.required + sreg_req.optional])
        sreg_resp = SRegResponse.extractResponse(sreg_req, user_data)
        sreg_resp.toMessage(response.fields)

def cgi_main(cfg):
    global query
    global request
    ostore = FileOpenIDStore(cfg.session_dir)
    oserver = OpenIDServer(ostore)

    # Get CGI fields and put into a dict
    fields = cgi.FieldStorage(keep_blank_values = True)
    query = {}
    for key in list(fields.keys()):
        query[key] = fields.getfirst(key)
    passphrase = query.pop('passphrase', None)

    # Decode request
    try:
        request = oserver.decodeRequest(query)
    except server.ProtocolError as err:
        logging.warn("Not an OpenID request: " + str(err))
        request = None

    if not request:
        print("Content-Type: text/plain\n")
        pprint.pprint(dict(os.environ))
        logging.shutdown()
        return

    # Redirect to HTTPS if required
    if type(request) == CheckIDRequest and \
            cfg.force_https() and \
            ('HTTPS' not in os.environ or os.environ['HTTPS'] != 'on'):
        print("Location: https://%s%s\n" % (os.environ['HTTP_HOST'], os.environ['REQUEST_URI']))
        return

    cookie = OpenIDSessionCookie(os.environ.get('HTTP_COOKIE', ''))

    # Read key from file
    global auth_key
    auth_key = OpenIDKey(cfg)

    response = None

    if type(request) == CheckIDRequest:
        # Reject if identity is not accepable
        if not cfg.validate_id(request.identity):
            response = request.answer(False)
        else:
            response = check_session()
            if not response and not request.immediate:
                response = check_passphrase(cfg, passphrase)
                #response = cfg.validate_passphrase(passphrase)

            response = request.answer(response)
            handle_sreg(request, response)
    else:
        try:
            response = oserver.handleRequest(request)
        except NotImplementedError:
            print('Status: 406 Not OpenID request')
            print('Content-Type: text/plain\n')
            return


    ostore.cleanup()

    # encode response
    response = oserver.encodeResponse(response)


    # Output
    for header in response.headers.items():
        print('%s: %s' % header)
    print(cookie.output())
    print()
    print(response.body)

#######################################
# Commandline mode functions

def cli_main(cfg):
    logging.shutdown()


#-----------------------------

if __name__ == '__main__':
    # Initialize paths and server object
    key_dir = os.path.expanduser('~/.openid')
    sreg_file = key_dir + '/sreg'

    init_logger()

    if 'REQUEST_METHOD' in os.environ:
        try:
            cfg = ConfigManager()
        except configparser.ParsingError as e:
            logging.error('Unable to parse config file: {0}'.format(err))
        cgi_main(cfg)
    else:
        cfg = ConfigManager(True)
        cli_main(cfg)
