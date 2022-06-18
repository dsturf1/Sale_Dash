

from flask import Flask, render_template, request, redirect, url_for, make_response
from flask_awscognito import AWSCognitoAuthentication
from flask_cors import CORS
from flask_jwt_extended import set_access_cookies,  get_jwt_identity, JWTManager, verify_jwt_in_request
from keys import get_cognito_public_keys

from jwt.algorithms import RSAAlgorithm



# EB looks for an 'application' callable by default.
# app = Flask(__name__, template_folder='./templates')
app = Flask(__name__)

app.config['AWS_DEFAULT_REGION'] = 'us-east-1'
app.config['AWS_COGNITO_DOMAIN'] = 'https://dsturf-login-test.auth.us-east-1.amazoncognito.com'
app.config['AWS_COGNITO_USER_POOL_ID'] = 'us-east-1_s7z41WH1Y'
app.config['AWS_COGNITO_USER_POOL_CLIENT_ID'] = '5nclqdj4j2s0grki0ad1f5ef2'
app.config['AWS_COGNITO_USER_POOL_CLIENT_SECRET'] = '1lmqcl8945mrpvrmmk5a6b5cpt3ti0nghp3lusgmp9tareto9lks'
app.config['AWS_COGNITO_REDIRECT_URL'] = 'http://localhost:5000/loggedin'

# app.config["JWT_PUBLIC_KEY"] = RSAAlgorithm.from_jwk(get_cognito_public_keys())
app.config["JWT_PUBLIC_KEY"] = 'RS256'

# Here you can globally configure all the ways you want to allow JWTs to
# be sent to your web application. By default, this will be only headers.
app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies", "json", "query_string"]

# If true this will only allow the cookies that contain your JWTs to be sent
# over https. In production, this should always be set to True
app.config["JWT_COOKIE_SECURE"] = False

# Change this in your code!
app.config["JWT_SECRET_KEY"] = "super-secret"

aws_auth = AWSCognitoAuthentication(app)



jwt = JWTManager(app)

@app.route("/")
def index():
    return render_template("index.html")
    
@app.route("/login", methods=["GET", "POST"])
def login():
    return redirect(aws_auth.get_sign_in_url())

@app.route("/loggedin", methods=["GET"])
def logged_in():
    access_token = aws_auth.get_access_token(request.args)
    resp = make_response(redirect(url_for("protected")))
    set_access_cookies(resp, access_token, max_age=30 * 60)
    print(get_cognito_public_keys())
    return resp

@app.route("/secret")
def protected():
    verify_jwt_in_request()
    if get_jwt_identity():
        return render_template("secret.html")
    else:
        return redirect(aws_auth.get_sign_in_url())

# run the app.
if __name__ == "__main__":
    # Setting debug to True enables debug output. This line should be
    # removed before deploying a production app.
    app.debug = True
    app.run()