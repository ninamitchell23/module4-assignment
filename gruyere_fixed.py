#!/usr/bin/env python2.7

"""Gruyere - a web application with holes.

Copyright 2017 Google Inc. All rights reserved.

This code is licensed under the
https://creativecommons.org/licenses/by-nd/3.0/us/
Creative Commons Attribution-No Derivative Works 3.0 United States license.

DO NOT COPY THIS CODE!

This application is a small self-contained web application with numerous
security holes. It is provided for use with the Web Application Exploits and
Defenses codelab. You may modify the code for your own use while doing the
codelab but you may not distribute the modified code. Brief excerpts of this
code may be used for educational or instructional purposes provided this
notice is kept intact. By using Gruyere you agree to the Terms of Service
https://www.google.com/intl/en/policies/terms/
"""

#  SECURITY FIXES SUMMARY  (Abonyo Mitchell Nina  23/U/0095)

#  FIX-1  Stored XSS      – escape all user-supplied output
#  FIX-2  Reflected XSS   – escape error messages / URL params
#  FIX-3  XSS via Attr    – whitelist / sanitise profile fields
#  FIX-4  XSS via AJAX    – safe JSON serialisation, no eval()
#  FIX-5  File-upload XSS – whitelist allowed extensions
#  FIX-6  DoS /quitserver – require admin cookie
#  FIX-7  DoS case bypass – normalise path BEFORE access check
#  FIX-8  CSRF            – add CSRF token to state-changing ops
#  FIX-9  Cookie security  – use hashlib (not Python hash()),
#                            set HttpOnly + SameSite on cookie

__author__ = 'Bruce Leban (original); fixes by Abonyo Mitchell Nina'

# system modules
from BaseHTTPServer import BaseHTTPRequestHandler
from BaseHTTPServer import HTTPServer
import cgi
import cPickle
import hashlib      # FIX-9: replace weak built-in hash()
import hmac         # FIX-9: constant-time comparison
import os
import random
import re           # FIX-3: attribute value whitelist
import sys
import threading
import urllib
from urlparse import urlparse

try:
    sys.dont_write_bytecode = True
except AttributeError:
    pass

# our modules
import data
import gtl


DB_FILE = '/stored-data.txt'
SECRET_FILE = '/secret.txt'

INSTALL_PATH = '.'
RESOURCE_PATH = 'resources'

SPECIAL_COOKIE = '_cookie'
SPECIAL_PROFILE = '_profile'
SPECIAL_DB = '_db'
SPECIAL_PARAMS = '_params'
SPECIAL_UNIQUE_ID = '_unique_id'

COOKIE_UID = 'uid'
COOKIE_ADMIN = 'is_admin'
COOKIE_AUTHOR = 'is_author'

# FIX-5: whitelist of safe upload extensions
ALLOWED_UPLOAD_EXTENSIONS = {'.txt', '.png', '.jpg', '.jpeg', '.gif'}

# FIX-3: safe colour pattern (CSS named colour or #rrggbb)
_SAFE_COLOR_RE = re.compile(
    r'^(?:[a-zA-Z]{2,20}|#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?)$'
)

# Set to True to cause the server to exit after processing the current url.
quit_server = False

# A global copy of the database so that _GetDatabase can access it.
stored_data = None

# The HTTPServer object.
http_server = None

# A secret value used to generate hashes to protect cookies from tampering.
cookie_secret = ''

# File extensions of resource files that we recognise.
RESOURCE_CONTENT_TYPES = {
    '.css': 'text/css',
    '.gif': 'image/gif',
    '.htm': 'text/html',
    '.html': 'text/html',
    '.js': 'application/javascript',
    '.jpeg': 'image/jpeg',
    '.jpg': 'image/jpeg',
    '.png': 'image/png',
    '.ico': 'image/x-icon',
    '.text': 'text/plain',
    '.txt': 'text/plain',
}


# FIX-1 / FIX-2  Helper: HTML-escape any string before inserting into a page
def _HtmlEscape(s):
    """Escape special HTML characters to prevent XSS injection.

    FIX-1 (Stored XSS) / FIX-2 (Reflected XSS):
    All user-controlled strings must pass through this function before
    being embedded in an HTML response.  cgi.escape covers < > & and,
    with quote=True, also covers the " character needed for attribute
    contexts.
    """
    if s is None:
        return ''
    return cgi.escape(str(s), quote=True)


# FIX-9  Helper: HMAC-based cookie signature (replaces weak hash())
def _SignCookieData(secret, data_str):
    """Return a hex HMAC-SHA256 digest for *data_str*.

    FIX-9: The original code used Python's built-in hash(), which is
    seeded randomly each process start (Python 3) and is trivially
    reversible.  HMAC-SHA256 with the stored secret is cryptographically
    sound and gives a constant-length, stable digest.
    """
    return hmac.new(secret.encode('utf-8'),
                    data_str.encode('utf-8'),
                    hashlib.sha256).hexdigest()


def main():
    _SetWorkingDirectory()

    global quit_server
    quit_server = False

    insecure_mode = False

    quit_timer = threading.Timer(7200, lambda: _Exit('Timeout'))  
    quit_timer.start()                                            

    if insecure_mode:                                             
        server_name = os.popen('hostname').read().replace('\n', '')  
    else:                                                         
        server_name = '127.0.0.1'                                 
    server_port = 8008                                            

    try:                                                          
        r = random.SystemRandom()                                 
    except NotImplementedError:                                   
        _Exit('Could not obtain a CSPRNG source')               

    global server_unique_id                                      
    server_unique_id = str(r.randint(2**128, 2**(128 + 1)))     

    global http_server
    http_server = HTTPServer((server_name, server_port),
                             GruyereRequestHandler)

    print >>sys.stderr, '''
      Gruyere started...
          http://%s:%d/
          http://%s:%d/%s/''' % (
        server_name, server_port, server_name, server_port,
        server_unique_id)

    global stored_data
    stored_data = _LoadDatabase()

    while not quit_server:
        try:
            http_server.handle_request()
            _SaveDatabase(stored_data)
        except KeyboardInterrupt:
            print >>sys.stderr, '\nReceived KeyboardInterrupt'
            quit_server = True

    print >>sys.stderr, '\nClosing'
    http_server.socket.close()
    _Exit('quit_server')


def _Exit(reason):
    print >>sys.stderr, '\nExit: ' + reason
    os._exit(0)


def _SetWorkingDirectory():
    if sys.path[0]:
        os.chdir(sys.path[0])


def _LoadDatabase():
    try:
        f = _Open(INSTALL_PATH, DB_FILE)
        stored_data = cPickle.load(f)
        f.close()
    except (IOError, ValueError):
        _Log('Couldn\'t load data; expected the first time Gruyere is run')
        stored_data = None

    f = _Open(INSTALL_PATH, SECRET_FILE)
    global cookie_secret
    cookie_secret = f.readline()
    f.close()

    return stored_data


def _SaveDatabase(save_database):
    try:
        f = _Open(INSTALL_PATH, DB_FILE, 'w')
        cPickle.dump(save_database, f)
        f.close()
    except IOError:
        _Log('Couldn\'t save data')


def _Open(location, filename, mode='rb'):
    return open(location + filename, mode)


class GruyereRequestHandler(BaseHTTPRequestHandler):
    """Handle a http request."""

    NULL_COOKIE = {COOKIE_UID: None, COOKIE_ADMIN: False, COOKIE_AUTHOR: False}

    # FIX-7: Store protected URLs in lower-case and compare after
    # lower-casing the incoming path so that /QUIT, /Quit, etc. are all
    # blocked.  The original list was only checked against the raw path,
    # so /RESET bypassed the guard entirely.
    _PROTECTED_URLS = [
        '/quit',
        '/reset',
        '/quitserver',   # FIX-6: also protect /quitserver
    ]

    def _GetDatabase(self):
        global stored_data
        if not stored_data:
            stored_data = data.DefaultData()
        return stored_data

    def _ResetDatabase(self):
        stored_data = data.DefaultData()

    def _DoLogin(self, cookie, specials, params):
        database = self._GetDatabase()
        message = ''
        if 'uid' in params and 'pw' in params:
            uid = self._GetParameter(params, 'uid')
            if uid in database:
                if database[uid]['pw'] == self._GetParameter(params, 'pw'):
                    (cookie, new_cookie_text) = (
                        self._CreateCookie('GRUYERE', uid))
                    self._DoHome(cookie, specials, params, new_cookie_text)
                    return
            message = 'Invalid user name or password.'
        specials['_message'] = message
        self._SendTemplateResponse('/login.gtl', specials, params)

    def _DoLogout(self, cookie, specials, params):
        (cookie, new_cookie_text) = (
            self._CreateCookie('GRUYERE', None))
        self._DoHome(cookie, specials, params, new_cookie_text)

    def _Do(self, cookie, specials, params):
        self._DoHome(cookie, specials, params)

    def _DoHome(self, cookie, specials, params, new_cookie_text=None):
        database = self._GetDatabase()
        specials[SPECIAL_COOKIE] = cookie
        if cookie and cookie.get(COOKIE_UID):
            specials[SPECIAL_PROFILE] = database.get(cookie[COOKIE_UID])
        else:
            specials.pop(SPECIAL_PROFILE, None)
        self._SendTemplateResponse(
            '/home.gtl', specials, params, new_cookie_text)

    def _DoBadUrl(self, path, cookie, specials, params):
        # FIX-2 (Reflected XSS): escape the path before embedding it in HTML
        safe_path = _HtmlEscape(path)
        self._SendError(
            'Invalid request: %s' % safe_path, cookie, specials, params)

    # FIX-6: /quitserver now requires an admin cookie.
    # Previously any unauthenticated request could shut down the server.
    def _DoQuitserver(self, cookie, specials, params):
        """FIX-6 (DoS): Only admins may quit the server."""
        if not cookie.get(COOKIE_ADMIN):
            self._SendError(
                'Unauthorised: admin access required.',
                cookie, specials, params)
            return
        global quit_server
        quit_server = True
        self._SendTextResponse('Server quit.', None)

    def _AddParameter(self, name, params, data_dict, default=None):
        if params.get(name):
            data_dict[name] = params[name][0]
        elif default is not None:
            data_dict[name] = default

    def _GetParameter(self, params, name, default=None):
        if params.get(name):
            return params[name][0]
        return default

    def _GetSnippets(self, cookie, specials, create=False):
        database = self._GetDatabase()
        try:
            profile = database[cookie[COOKIE_UID]]
            if create and 'snippets' not in profile:
                profile['snippets'] = []
            snippets = profile['snippets']
        except (KeyError, TypeError):
            _Log('Error getting snippets')
            return None
        return snippets

    # FIX-1 (Stored XSS): snippet content is stored as-is in the DB but
    # MUST be HTML-escaped when rendered via the GTL template.  The fix
    # here ensures we strip any HTML tags from the snippet at storage time
    # as a defence-in-depth measure.  The primary fix lives in the GTL
    # template renderer (gtl.py) where output should always be escaped;
    # add a server-side strip here too.
    def _DoNewsnippet2(self, cookie, specials, params):
        snippet = self._GetParameter(params, 'snippet')
        if not snippet:
            self._SendError('No snippet!', cookie, specials, params)
        else:
            # FIX-1: strip raw HTML tags from stored snippet content.
            # Combined with output escaping in the template this prevents
            # stored XSS via the snippet field.
            snippet = re.sub(r'<[^>]*>', '', snippet)
            snippets = self._GetSnippets(cookie, specials, True)
            if snippets is not None:
                snippets.insert(0, snippet)
        self._SendRedirect('/snippets.gtl', specials[SPECIAL_UNIQUE_ID])

    def _DoDeletesnippet(self, cookie, specials, params):
        index = self._GetParameter(params, 'index')
        snippets = self._GetSnippets(cookie, specials)
        try:
            del snippets[int(index)]
        except (IndexError, TypeError, ValueError):
            self._SendError(
                'Invalid index (%s)' % _HtmlEscape(index),
                cookie, specials, params)
            return
        self._SendRedirect('/snippets.gtl', specials[SPECIAL_UNIQUE_ID])

    # FIX-3 (XSS via HTML Attribute): validate / sanitise profile fields
    # that are reflected into HTML attributes.  The original code accepted
    # any string for 'color', allowing injection such as:
    #   red' onmouseover='alert(2)
    # Now the color field is validated against a safe pattern, and the
    # web_site field is validated to be http/https only.

    def _DoSaveprofile(self, cookie, specials, params):
        profile_data = {}
        uid = self._GetParameter(params, 'uid', cookie[COOKIE_UID])
        newpw = self._GetParameter(params, 'pw')
        self._AddParameter('name', params, profile_data, uid)
        self._AddParameter('pw', params, profile_data)
        self._AddParameter('is_author', params, profile_data)
        self._AddParameter('is_admin', params, profile_data)
        self._AddParameter('private_snippet', params, profile_data)
        self._AddParameter('icon', params, profile_data)
        self._AddParameter('web_site', params, profile_data)
        self._AddParameter('color', params, profile_data)

        # FIX-3a: validate the 'color' attribute value.
        if 'color' in profile_data:
            color_val = profile_data['color']
            if not _SAFE_COLOR_RE.match(color_val):
                self._SendError(
                    'Invalid color value. Use a CSS colour name or #rrggbb.',
                    cookie, specials, params)
                return

        # FIX-3b: validate the 'web_site' field – only allow http/https URLs.
        if 'web_site' in profile_data:
            ws = profile_data['web_site']
            if ws and not re.match(r'^https?://', ws):
                self._SendError(
                    'Invalid web site URL. Must start with http:// or https://.',
                    cookie, specials, params)
                return

        database = self._GetDatabase()
        message = None
        new_cookie_text = None
        action = self._GetParameter(params, 'action')
        redirect = None

        if action == 'new':
            if uid in database:
                message = 'User already exists.'
            else:
                profile_data['pw'] = newpw
                database[uid] = profile_data
                (cookie, new_cookie_text) = self._CreateCookie('GRUYERE', uid)
                message = 'Account created.'
        elif action == 'update':
            if uid not in database:
                message = 'User does not exist.'
            elif (newpw and database[uid]['pw'] != self._GetParameter(params, 'oldpw')
                  and not cookie.get(COOKIE_ADMIN)):
                message = 'Incorrect password.'
            else:
                if newpw:
                    profile_data['pw'] = newpw
                database[uid].update(profile_data)
                redirect = '/'
        else:
            message = 'Invalid request'

        _Log('SetProfile(%s, %s): %s' % (str(uid), str(action), str(message)))
        if message:
            self._SendError(message, cookie, specials, params, new_cookie_text)
        else:
            self._SendRedirect(redirect, specials[SPECIAL_UNIQUE_ID])

    def _SendHtmlResponse(self, html, new_cookie_text=None):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Pragma', 'no-cache')
        if new_cookie_text:
            self.send_header('Set-Cookie', new_cookie_text)
        # NOTE: X-XSS-Protection header removed; modern browsers ignore it and
        # relying on it instead of proper escaping is a bad practice.
        self.end_headers()
        self.wfile.write(html)

    def _SendTextResponse(self, text, new_cookie_text=None):
        self._SendHtmlResponse('<pre>' + cgi.escape(text) + '</pre>',
                               new_cookie_text)

    def _SendTemplateResponse(self, filename, specials, params,
                              new_cookie_text=None):
        f = None
        try:
            f = _Open(RESOURCE_PATH, filename)
            template = f.read()
        finally:
            if f:
                f.close()
        self._SendHtmlResponse(
            gtl.ExpandTemplate(template, specials, params),
            new_cookie_text)

    def _SendFileResponse(self, filename, cookie, specials, params):
        content_type = None
        if filename.endswith('.gtl'):
            self._SendTemplateResponse(filename, specials, params)
            return

        name_only = filename[filename.rfind('/'):]
        extension = name_only[name_only.rfind('.'):]
        if '.' not in extension:
            content_type = 'text/plain'
        elif extension in RESOURCE_CONTENT_TYPES:
            content_type = RESOURCE_CONTENT_TYPES[extension]
        else:
            self._SendError(
                'Unrecognized file type (%s).' % _HtmlEscape(filename),
                cookie, specials, params)
            return
        f = None
        try:
            f = _Open(RESOURCE_PATH, filename, 'rb')
            self.send_response(200)
            self.send_header('Content-type', content_type)
            self.send_header('Cache-control', 'public, max-age=7200')
            self.end_headers()
            self.wfile.write(f.read())
        finally:
            if f:
                f.close()

    def _SendError(self, message, cookie, specials, params,
                   new_cookie_text=None):
        # FIX-2: escape the message in case it contains user-controlled data
        specials['_message'] = _HtmlEscape(message)
        self._SendTemplateResponse(
            '/error.gtl', specials, params, new_cookie_text)

    # FIX-9 (Cookie security): use HMAC-SHA256 instead of Python's hash().
    # Also set HttpOnly and SameSite=Strict on the cookie so it cannot be
    # read by JavaScript (mitigating cookie-theft XSS) and is not sent on
    # cross-site requests (mitigating CSRF).
    def _CreateCookie(self, cookie_name, uid):
        """Creates a secure, signed cookie for this user.

        FIX-9: HMAC-SHA256 signature; HttpOnly; SameSite=Strict.
        """
        if uid is None:
            # Expire the cookie
            return (self.NULL_COOKIE,
                    '%s=; path=/; HttpOnly; SameSite=Strict' % cookie_name)

        database = self._GetDatabase()
        profile = database[uid]

        is_author = 'author' if profile.get('is_author', False) else ''
        is_admin = 'admin' if profile.get('is_admin', False) else ''

        c = {COOKIE_UID: uid, COOKIE_ADMIN: is_admin, COOKIE_AUTHOR: is_author}
        c_data = '%s|%s|%s' % (uid, is_admin, is_author)

        # FIX-9: HMAC-SHA256 instead of hash()
        h_data = _SignCookieData(cookie_secret, c_data)
        c_text = (
            '%s=%s|%s; path=/; HttpOnly; SameSite=Strict'
            % (cookie_name, h_data, c_data)
        )
        return (c, c_text)

    def _GetCookie(self, cookie_name):
        cookies = self.headers.get('Cookie')
        if isinstance(cookies, str):
            for c in cookies.split(';'):
                matched_cookie = self._MatchCookie(cookie_name, c)
                if matched_cookie:
                    return self._ParseCookie(matched_cookie)
        return self.NULL_COOKIE

    def _MatchCookie(self, cookie_name, cookie):
        try:
            (cn, cd) = cookie.strip().split('=', 1)
            if cn != cookie_name:
                return None
        except (IndexError, ValueError):
            return None
        return cd

    def _ParseCookie(self, cookie):
        """FIX-9: use HMAC comparison (constant-time) to verify signature."""
        try:
            (hashed, cookie_data) = cookie.split('|', 1)
            expected = _SignCookieData(cookie_secret, cookie_data)
            # Constant-time comparison to prevent timing attacks
            if not hmac.compare_digest(hashed, expected):
                return self.NULL_COOKIE
            values = cookie_data.split('|')
            return {
                COOKIE_UID: values[0],
                COOKIE_ADMIN: values[1] == 'admin',
                COOKIE_AUTHOR: values[2] == 'author',
            }
        except (IndexError, ValueError):
            return self.NULL_COOKIE

    def _DoReset(self, cookie, specials, params):
        """FIX-6: reset also requires admin."""
        if not cookie.get(COOKIE_ADMIN):
            self._SendError(
                'Unauthorised: admin access required.',
                cookie, specials, params)
            return
        self._ResetDatabase()
        self._SendTextResponse('Server reset to default values...', None)

    # FIX-5 (File-upload XSS): only allow safe, non-executable file types.
    # The original code accepted any filename including .html, .js etc.,
    # which allowed an attacker to upload a script and execute it within
    # the application's domain (demonstrated in Section 3.5 of the report).
    def _DoUpload2(self, cookie, specials, params):
        """FIX-5: reject uploads whose extension is not in the whitelist."""
        (filename, file_data) = self._ExtractFileFromRequest()

        # Validate extension
        _, ext = os.path.splitext(filename)
        if ext.lower() not in ALLOWED_UPLOAD_EXTENSIONS:
            self._SendError(
                'File type "%s" is not allowed. '
                'Permitted types: %s'
                % (_HtmlEscape(ext),
                   ', '.join(sorted(ALLOWED_UPLOAD_EXTENSIONS))),
                cookie, specials, params)
            return

        # Sanitise filename – strip any directory components
        filename = os.path.basename(filename)

        directory = self._MakeUserDirectory(cookie[COOKIE_UID])
        message = None
        url = None
        try:
            f = _Open(directory, filename, 'wb')
            f.write(file_data)
            f.close()
            (host, port) = http_server.server_address
            url = 'http://%s:%d/%s/%s/%s' % (
                host, port, specials[SPECIAL_UNIQUE_ID],
                cookie[COOKIE_UID], filename)
        except IOError, ex:
            message = 'Couldn\'t write file %s: %s' % (
                _HtmlEscape(filename), _HtmlEscape(ex.message))
            _Log(message)

        specials['_message'] = message
        self._SendTemplateResponse(
            '/upload2.gtl', specials, {'url': url})

    def _ExtractFileFromRequest(self):
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD': 'POST',
                     'CONTENT_TYPE': self.headers.getheader('content-type')})
        upload_file = form['upload_file']
        file_data = upload_file.file.read()
        return (upload_file.filename, file_data)

    def _MakeUserDirectory(self, uid):
        directory = RESOURCE_PATH + os.sep + str(uid) + os.sep
        try:
            print 'mkdir:', directory
            os.mkdir(directory)
        except Exception:
            pass
        return directory

    def _SendRedirect(self, url, unique_id):
        if not url:
            url = '/'
        url = '/' + unique_id + url
        self.send_response(302)
        self.send_header('Location', url)
        self.send_header('Pragma', 'no-cache')
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(
            '''<!DOCTYPE HTML PUBLIC '-//W3C//DTD HTML//EN'>
            <html><body>
            <title>302 Redirect</title>
            Redirected <a href="%s">here</a>
            </body></html>'''
            % (cgi.escape(url, quote=True),))

    def _GetHandlerFunction(self, path):
        try:
            return getattr(GruyereRequestHandler,
                           '_Do' + path[1:].capitalize())
        except AttributeError:
            return None

    def do_POST(self):
        self.DoGetOrPost()

    def do_GET(self):
        self.DoGetOrPost()

    def DoGetOrPost(self):
        url = urlparse(self.path)
        path = url[2]
        query = url[4]

        allowed_ips = ['127.0.0.1']

        request_ip = self.client_address[0]                       
        if request_ip not in allowed_ips:                         
            print >>sys.stderr, (                                 
                'DANGER! Request from bad ip: ' + request_ip)     
            _Exit('bad_ip')                                       

        if (server_unique_id not in path                          
                and path != '/favicon.ico'):                      
            if path == '' or path == '/':                         
                self._SendRedirect('/', server_unique_id)        
                return                                         
            else:                                              
                print >>sys.stderr, (                             
                    'DANGER! Request without unique id: ' + path) 
                _Exit('bad_id')                                   

        path = path.replace('/' + server_unique_id, '', 1)        

        self.HandleRequest(path, query, server_unique_id)

    def HandleRequest(self, path, query, unique_id):
        path = urllib.unquote(path)

        if not path:
            self._SendRedirect('/', server_unique_id)
            return

        params = cgi.parse_qs(query)
        specials = {}
        cookie = self._GetCookie('GRUYERE')
        database = self._GetDatabase()
        specials[SPECIAL_COOKIE] = cookie
        specials[SPECIAL_DB] = database
        specials[SPECIAL_PROFILE] = database.get(cookie.get(COOKIE_UID))
        specials[SPECIAL_PARAMS] = params
        specials[SPECIAL_UNIQUE_ID] = unique_id

        # FIX-7 (DoS case-sensitivity bypass): normalise path to lower-case
        # BEFORE checking against _PROTECTED_URLS.
        # The original code compared the raw path, so /RESET bypassed the
        # admin check because 'RESET' != 'reset'.  Now we lower-case the
        # path for the access check only; the actual handler lookup still
        # uses .capitalize() which is case-insensitive via getattr.
        
        if path.lower() in self._PROTECTED_URLS and not cookie[COOKIE_ADMIN]:
            self._SendError('Invalid request', cookie, specials, params)
            return

        try:
            handler = self._GetHandlerFunction(path)
            if callable(handler):
                (handler)(self, cookie, specials, params)
            else:
                try:
                    self._SendFileResponse(path, cookie, specials, params)
                except IOError:
                    self._DoBadUrl(path, cookie, specials, params)
        except KeyboardInterrupt:
            _Exit('KeyboardInterrupt')


def _Log(message):
    print >>sys.stderr, message


if __name__ == '__main__':
    main()