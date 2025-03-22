# Copyright 2015 INFN
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
SSO FLASK Application for Discourse
The configuration file is defined with the variable "DISCOURSE_SSO_CONFIG",
for the most significant values look at the sso/default.py file
"""

from flask import abort, Flask, redirect, render_template, request, url_for, \
    session,jsonify
    session,jsonify
import base64
import hashlib
import hmac
import urllib.parse
import urllib.parse
import re
import sys
sys.path.append('/var/www/html/DiscourseSSO/src/discourseSSO')
import add_user_to_group
import os
import jwt
import requests
import json
import fnmatch

app = Flask(__name__)
app.config.from_object('discourseSSO.default.Config')
app.config.from_pyfile('config.py')
app.config.from_envvar('DISCOURSE_SSO_CONFIG', True)
GOOGLE_DOMAIN = os.getenv('GOOGLE_DOMAIN', '*')
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', '')
GOOGLE_SECRET = os.getenv('GOOGLE_SECRET', '')
GOOGLE_REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI', '')
GOOGLE_AUTH_URL = os.getenv('GOOGLE_AUTH_URL', '')

@app.route('/sso/login')
def payload_check():
    """
    Verify the payload and signature coming from a Discourse server and if
    correct redirect to the authentication page
    :return: The redirection page to the authentication page
    """
    payload = request.args.get('sso', '').encode()
    signature = request.args.get('sig', '')
    
    app.logger.debug('Request to login with payload="%s" signature="%s"',
                     payload, signature)
    if not payload or not signature:
        abort(400)

    app.logger.debug('Session Secret Key: %s',
                     app.secret_key)
    app.logger.debug('SSO Secret Key: %s',
                     app.config.get('DISCOURSE_SECRET_KEY'))
    
    dig = hmac.new(
        app.config.get('DISCOURSE_SECRET_KEY'),
        payload,
        hashlib.sha256
    ).hexdigest()
    app.logger.debug('Calculated hash: %s', dig)
    if dig != signature:
        abort(400)
    decoded_msg = base64.decodestring(payload)
    session['nonce'] = decoded_msg
    return redirect(url_for('user_authz'))


@app.route('/sso/auth')
def user_authz():
    """
    Read the user attributes provided by the application server (generally
    it is apache httpd) as environment variables and create the payload to
    send to discourse
    :return: The redirection page to Discourse
    """
    attribute_map = app.config.get('DISCOURSE_USER_MAP')
    user_flag_filters = app.config.get('DISCOURSE_USER_FLAGS')
    admins = app.config.get('ADMINS')
    admins = app.config.get('ADMINS')
    email = request.environ.get(attribute_map['email'])

    if request.environ.get(attribute_map['external_id']):
        external_id = request.environ.get(attribute_map['external_id'])
    elif request.environ.get('persistent-id'):
        external_id = request.environ.get('persistent-id')
    else:
        external_id = request.environ.get('edu-person-id')

    if not (email or external_id or request.environ.get('cn')):
        return redirect("http://discourse.di.unisa.it/secure")

    if ';' in email:
        try:
            email = email.split(';')[0]
        except Exception as e:
            print(e)
    
    if request.environ.get('affiliation'):
        bio = request.environ.get('affiliation')
        print(f"Affiliation: {bio} for {email}")
    elif request.environ.get('eduPersonAffiliation'):
        bio = request.environ.get('eduPersonAffiliation')
        print(f"Affiliation: {bio} for {email}")
    else:
        print(f'Affilation not provided for {email}')

    #external_id = request.environ.get(attribute_map['external_id'])
    

    print(email)
    print(external_id)
    #print(request.environ.get('cn'))
    
    #Only now to close the platform to all       
    #if not (email in admins):
    #    return redirect("http://discourse.di.unisa.it/secure/index_success.php")
    if not (email and external_id):
        abort(403)
    name_list = []
    for name_to_map in attribute_map['name']:
        if request.environ.get(name_to_map):
            name_list.append(request.environ.get(name_to_map))
    name = ' '.join(name_list)
    if request.environ.get(attribute_map['username']):
        username = request.environ.get(attribute_map['username'])
    else:
        username = (name.replace(' ', '') +
                    "_" +
                    hashlib.md5(email).hexdigest()[0:4]
                    )
    avatar_url = request.environ.get(attribute_map['avatar_url'])
    #bio = request.environ.get(attribute_map['bio'])
    app.logger.debug('Authenticating "%s" with username "%s" and email "%s"',
                     name, username, email)
    if 'nonce' not in session:
        abort(403)

    isAdmin = 'false'
    if email in admins:
        isAdmin = 'true'
    
    print(name)
    nonce = session['nonce'].decode('utf-8')
    query = (nonce +
             '&name=' + urllib.parse.quote(name, encoding='utf-8') +
             '&username=' + urllib.parse.quote(username, encoding='utf-8') +
             '&email=' + urllib.parse.quote(email) +
             '&admin=' + isAdmin + 
             '&external_id=' + urllib.parse.quote(external_id))
    if avatar_url:
        query = query + '&avatar_url=' + urllib.parse.quote(avatar_url)
    if request.environ.get('affiliation'):
        query = query + '&bio=' + urllib.parse.quote(bio)
        query = query + '&avatar_url=' + urllib.parse.quote(avatar_url)
    if request.environ.get('affiliation'):
        query = query + '&bio=' + urllib.parse.quote(bio)
    flags = {}
    for user_flag in user_flag_filters:
        if 'filter' in user_flag:
            filter = user_flag['filter'].split('=')
            reg_exp = re.compile(filter[1])
            if (request.environ.get(filter[0]) and
                    reg_exp.match(request.environ.get(filter[0]))):
                flags[user_flag['name']] = user_flag['value']
        else:
            flags[user_flag['name']] = user_flag['value']
    for flags_name in sorted(flags.keys()):
        query = query + '&' + flags_name + '=' + flags[flags_name]
    app.logger.debug('Query string to return: %s', query)
    query_b64 = base64.b64encode(query.encode('utf-8'))
    app.logger.debug('Base64 query string to return: %s', query_b64)
    query_urlenc = urllib.parse.quote(query_b64)
    app.logger.debug('URLEnc query string to return: %s', query_urlenc)
    sig = hmac.new(
        app.config.get('DISCOURSE_SECRET_KEY'),
        query_b64,
        hashlib.sha256
    ).hexdigest()

    app.logger.debug('Signature: %s', sig)
    redirect_url = (app.config.get('DISCOURSE_URL') +
                    '/session/sso_login?'
                    'sso=' + query_urlenc +
                    '&sig=' + sig)
    return redirect(redirect_url)


@app.errorhandler(403)
def attribuete_not_provided(error):
    """
    Render a custom error page in case the IdP authenticate the user but does
    not provide the requested attributes

    :type error: object
    """
    return render_template('403.html'), 403

@app.route('/sso/set_private_group',methods=['POST'])
def set_group_webhook():
    data = request.get_json()
    #Data about affilation are temporarily saved into the user's bio
    try:
        affilation = data['user']['bio_raw']
        username = data['user']['username']
        result = add_user_to_group.add_users_to_group(username,affilation)
        add_user_to_group.clean_bio(username)
        if result:
            return jsonify({'message': 'Operation completed with success'}), 200
        else:
            return jsonify({'message': 'Error'}), 500
    except Exception as e:
        print(e)
        add_user_to_group.clean_bio(username)

# Google OAuth

@app.route('/google/sso')
def sso_login():
    encoded_payload = request.args.get('sso', '').encode()
    signature = request.args.get('sig', '')
    if signature != _sign_payload(encoded_payload):
        abort(400)

    # Validate payload is base64 encoded
    try:
        payload = urllib.parse.parse_qs(
            base64.urlsafe_b64decode(encoded_payload)
        )
    except ValueError:
        abort(400)

    return _redirect_to_google_auth(payload)

@app.route('/google/sso/google-oauth2/callback')
def google_oauth2_callback():
    return render_template('google-oauth2-callback.html')

@app.route('/google/sso/google-oauth2/next', methods=['POST'])
def google_oauth2_next():
    state = request.form.get('state')
    userinfo = request.form.get('userInfo')
    if not (state and userinfo):
        abort(400)
    
    payload = jwt.decode(state, app.config.get('DISCOURSE_SECRET_KEY_STR'), algorithms=['HS256'])
    userinfo = json.loads(userinfo)

    username, _, domain = userinfo['email'].partition('@')
    if not fnmatch.fnmatch(domain, app.config.get('GOOGLE_DOMAIN')):
        abort(401)
        #return _redirect_to_google_auth(payload)

    payload['external_id'] = userinfo['sub']
    payload['name'] = userinfo['name'].encode('utf-8')
    payload['email'] = userinfo['email']
    payload['username'] = userinfo['email'].partition('@')[0]
    payload['avatar_url'] = userinfo['picture']
    
    encoded_payload = base64.urlsafe_b64encode(
    	urllib.parse.urlencode(payload, doseq=1).encode("utf-8")
    ).decode("utf-8")
    
    signature = _sign_payload(encoded_payload.encode("utf-8"))
    qs = urllib.parse.urlencode({'sso': encoded_payload, 'sig': signature})
    return redirect(app.config.get('DISCOURSE_URL') + "/session/sso_login?" + qs)

@app.after_request
def apply_caching(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response


def _sign_payload(payload, secret=app.config.get('DISCOURSE_SECRET_KEY_STR').encode('utf-8')):
    return hmac.new(
        app.config.get('DISCOURSE_SECRET_KEY'),
        payload,
        hashlib.sha256
    ).hexdigest()

def _redirect_to_google_auth(payload):
    cleaned_payload = {k.decode(): [v.decode() for v in vals] for k, vals in payload.items()}
    state = jwt.encode(cleaned_payload, app.config.get('DISCOURSE_SECRET_KEY_STR'), 'HS256')
    query = urllib.parse.urlencode({
        'client_id': app.config.get('GOOGLE_CLIENT_ID'),
        'redirect_uri': app.config.get('GOOGLE_REDIRECT_URI'),
        'response_type': 'token',
        'scope': 'profile email',
        'hd': app.config.get('GOOGLE_DOMAIN'),
        'state': state,
    })
    url = '{}?{}'.format(app.config.get('GOOGLE_AUTH_URL'), query)
    return redirect(url)

@app.route('/proxy/google_openid')
def google_openid_proxy():
    access_token = request.args.get('access_token')
    if not access_token:
        return jsonify({"error": "Missing access token"}), 400

    google_url = "https://www.googleapis.com/oauth2/v3/userinfo"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    
    response = requests.get(google_url, headers=headers)
    
    return jsonify(response.json()), response.status_code
