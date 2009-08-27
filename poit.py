#!/usr/bin/python

import cgi
import logging
import logging.handlers
import os
import sys
import pprint

import cgitb; cgitb.enable()

###########################################

import urllib

import openid
from openid.server import server
from openid.server.server import Server as OpenIDServer, CheckIDRequest, CheckAuthRequest
from openid.extensions.sreg import SRegRequest, SRegResponse
from openid.store.filestore import FileOpenIDStore

# Initialize paths and server object
key_dir = os.path.expanduser('~/.openid')
key_file = key_dir + '/key'
sreg_file = key_dir + '/sreg'
store_dir = key_dir + '/sessions'

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

init_logger()

if 'REQUEST_METHOD' not in os.environ:
    #pprint.pprint(dict(os.environ))
    pprint.pprint(config)
    logging.shutdown()
    sys.exit()

ostore = FileOpenIDStore(store_dir)
oserver = OpenIDServer(ostore, 'http://iwa.yangman.ca/openid')

# Get CGI fields and put into a dict
fields = cgi.FieldStorage(keep_blank_values = True)
query = {}
for key in fields.keys():
    query[key] = fields.getfirst(key)
passphrase = query.pop('passphrase', None)

# Decode request
request = oserver.decodeRequest(query)

if not request:
    print "Content-Type: text/plain\n"
    pprint.pprint(dict(os.environ))
    pprint.pprint(config)
    logging.shutdown()
    sys.exit()

# Redirect to HTTPS if required
if type(request) == CheckIDRequest and ('HTTPS' not in os.environ or os.environ['HTTPS'] != 'on'):
    print "Location: https://%s%s\n" % (os.environ['HTTP_HOST'], os.environ['REQUEST_URI'])
    sys.exit()
    
#-------------------------------------

import hashlib
from Cookie import SimpleCookie
import fileinput


class OpenIDSessionCookie(SimpleCookie):
    def set_timeout(self, timeout=3600):
        '''Set expiration of cookie timeout seconds into the future
        If 0, expire this cookie
        '''
        for o in self.itervalues():
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
    def __init__(self, keyfile):
        self.__allowed_ids = []
        try:
            f = fileinput.FileInput(keyfile)
            self.md5 = f.readline().rstrip()
            self.sha512 = f.readline().rstrip()

            for line in f:
                self.__allowed_ids.append(line.rstrip())
            f.close()
        except:
            self.md5 = None
            self.sha512 = None

    def valid_id(self, id):
        return (id in self.__allowed_ids)
        
    def validate(self, key):
        '''Validate a passphrase or cookie'''
        if type(key) == str:
            if not (self.md5 and self.sha512): return False

            h = hashlib.md5()
            h.update(passphrase)
            if h.hexdigest() != self.md5: return False

            h = hashlib.sha512()
            h.update(passphrase)
            if h.hexdigest() != self.sha512: return False

            return True

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
        h.update(self.md5)
        h.update(salt)
        h.update(self.sha512)
        key = h.hexdigest()

        cookie = OpenIDSessionCookie()
        cookie.set_hash('openid_1', salt)
        cookie.set_hash('openid_2', key)

        return cookie
    

cookie = OpenIDSessionCookie(os.environ.get('HTTP_COOKIE', ''))

# Read key from file
auth_key = OpenIDKey(key_file)

def check_passphrase():
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
        print "Content-Type: text/html\n"
        print '''<html><head><title>OpenID authenticate</title></head>
            <body>
            <form action="%s" method="post">
                <input type="password" name="passphrase" size="20" />
                <button type="submit">Authorize</button>''' % (re.sub(r'^http:', 'https:', os.environ['REDIRECT_URL']),)

        for p in query.iteritems():
            print '<input type="hidden" name="%s" value="%s" />' % p

        print '</form>'
        print '<a href="%s">Reject</a>' % (request.getCancelURL(),)
        print '</body></html>'
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
    print 'Content-Type: text/plain\n'
    print os.environ
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


#-----------------------------

response = None

if type(request) == CheckIDRequest:
    # Reject if identity is not accepable
    if not auth_key.valid_id(request.identity):
        response = request.answer(False)
    else:
        response = check_session()
        if not response and not request.immediate:
            response = check_passphrase()

        response = request.answer(response)
        handle_sreg(request, response)
else:
    try:
        response = oserver.handleRequest(request)
    except NotImplementedError:
        print 'Status: 406 Not OpenID request'
        print 'Content-Type: text/plain\n'
        import sys
        sys.exit()


ostore.cleanup()

# encode response
response = oserver.encodeResponse(response)


# Output
for header in response.headers.iteritems():
    print '%s: %s' % header
print cookie.output()
print
print response.body

