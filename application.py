from flask import Flask, redirect, request, jsonify, session, render_template_string,url_for
from flask_login import LoginManager,UserMixin,login_user, logout_user, login_required
import requests
from requests.auth import HTTPBasicAuth
import os
from datetime import datetime
from jose import jwt

import config

application = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(application)

application.secret_key = config.FLASK_SECRET





JWKS_URL = ("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json"
            % (config.AWS_DEFAULT_REGION, config.AWS_COGNITO_USER_POOL_ID))
JWKS = requests.get(JWKS_URL).json()["keys"]



class User(UserMixin):
    """Standard flask_login UserMixin"""
    pass

@login_manager.user_loader
def user_loader(session_token):
    """Populate user object, check expiry"""
    if "expires" not in session:
        return None

    expires = datetime.utcfromtimestamp(session['expires'])
    expires_seconds = (expires - datetime.utcnow()).total_seconds()
    if expires_seconds < 0:
        return None

    user = User()
    user.id = session_token
    user.email = session['email']
    user.groups = session['groups']
    return user

@application.route("/login")
def login():
    """Login route"""
    # http://docs.aws.amazon.com/cognito/latest/developerguide/login-endpoint.html
    session['csrf_state'] = os.urandom(8).hex()

    cognito_login = ("%s/"
                     "login?response_type=code&client_id=%s"
                     "&state=%s"
                     "&redirect_uri=%s" %
                     (config.AWS_COGNITO_DOMAIN, config.AWS_COGNITO_USER_POOL_CLIENT_ID, session['csrf_state'],
                      config.AWS_COGNITO_REDIRECT_URL))

    return redirect(cognito_login)

@application.route("/logout")
def logout():
    """Logout route"""
    # http://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html
    logout_user()
    cognito_logout = ("%s/"
                      "logout?response_type=code&client_id=%s"
                      "&logout_uri=%s/"
                        "&state=%s"
                      "&redirect_uri=%s" %
                     (config.AWS_COGNITO_DOMAIN, config.AWS_COGNITO_USER_POOL_CLIENT_ID,
                      config.AWS_COGNITO_LOGOUT_URL, session['csrf_state'],config.AWS_COGNITO_REDIRECT_URL))
    return redirect(cognito_logout)

@application.route("/callback")
def callback():
    """Exchange the 'code' for Cognito tokens"""
    #http://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html
    csrf_state = request.args.get('state')
    code = request.args.get('code')

    request_parameters = {'grant_type': 'authorization_code',
                          'client_id': config.AWS_COGNITO_USER_POOL_CLIENT_ID,
                          'code': code,
                          "redirect_uri" : config.AWS_COGNITO_REDIRECT_URL}
                          
    response = requests.post("%s/oauth2/token" % config.AWS_COGNITO_DOMAIN,
                             data=request_parameters,
                             auth=HTTPBasicAuth(config.AWS_COGNITO_USER_POOL_CLIENT_ID,
                                                config.AWS_COGNITO_USER_POOL_CLIENT_SECRET))

    # the response:
    # http://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html
    if response.status_code == requests.codes.ok and csrf_state == session['csrf_state']:

        print('reponse:',response.status_code,requests.codes.ok)
        print('reponse:',csrf_state,session['csrf_state'])


        verify(response.json()["access_token"])
        id_token = verify(response.json()["id_token"], response.json()["access_token"])

        print(id_token)

        user = User()
        user.id = id_token["cognito:username"]
        session['groups'] = id_token["cognito:groups"]
        session['email'] = id_token["email"]
        session['expires'] = id_token["exp"]
        session['refresh_token'] = response.json()["refresh_token"]
        login_user(user, remember=True)
        return redirect(url_for("home"))

    return render_template_string("""
        {% extends "main.html" %}
        {% block content %}
            <p>Something went wrong</p>
        {% endblock %}""")

@application.errorhandler(401)
def unauthorized(exception):
    "Unauthorized access route"
    return render_template_string("""
        {% extends "main.html" %}
        {% block content %}
            <p>Please login to access this page</p>
        {% endblock %}"""), 401

def verify(token, access_token=None):
    """Verify a cognito JWT"""
    # get the key id from the header, locate it in the cognito keys
    # and verify the key
    header = jwt.get_unverified_header(token)
    key = [k for k in JWKS if k["kid"] == header['kid']][0]
    id_token = jwt.decode(token, key, audience=config.AWS_COGNITO_USER_POOL_CLIENT_ID, access_token=access_token)


    return id_token


@application.route("/")
def home():
    """Homepage route"""
    return render_template_string("""
        {% extends "main.html" %}
        {% block content %}
        {{env1}}
        {% if current_user.is_authenticated %}
        Click <em>my photos</em> to access your photos.
        {% else %}
        Click <em>login in / sign up<em> to access this site.
        {% endif %}
        {% endblock %}""", env1 = config.FLASK_SECRET)

@application.route("/dswork", methods=('GET', 'POST'))
@login_required
def dswork():
    # html_out = work_df2.iloc[:1,:].to_html(float_format='{:20,.1f}'.format,classes='table table-stripped table-hover',table_id='dswork')

    # print({'data': work_df2.to_dict('records')})

    return render_template_string("""
        {% extends "main.html" %}
        {% block content %}
        {% if current_user.is_authenticated %}
        Click <em>Data!!!</em> to access your photos.
        {% else %}
        Click <em>login in / sign up<em> to access this site.
        {% endif %}
        {% endblock %}""")

# run the application.
if __name__ == "__main__":
    # Setting debug to True enables debug output. This line should be
    # removed before deploying a production application.
    application.debug = True
    application.run('localhost')