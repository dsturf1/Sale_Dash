from flask import Flask, redirect, request, jsonify, session, render_template_string,url_for,render_template
from flask_login import LoginManager,UserMixin,login_user, logout_user, login_required, current_user
import requests
from requests.auth import HTTPBasicAuth
import os
from datetime import datetime
from jose import jwt
import json
import pandas as pd
import plotly
import plotly.express as px
import plotly.graph_objects as go
from plotly.figure_factory import create_table
from plotly.subplots import make_subplots

import config

import pickle
import boto3
import boto3.session

# cred = boto3.Session().get_credentials()
# ACCESS_KEY = cred.access_key
# SECRET_KEY = cred.secret_key
# SESSION_TOKEN = cred.token  ## optional

# # print(cred.access_key)

work_df = pd.DataFrame([])
work_df2 = pd.DataFrame([])

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
    # cognito_logout = ("%s/"
    #                   "logout?response_type=code&client_id=%s"
    #                   "&logout_uri=%s/"
    #                     "&state=%s"
    #                   "&redirect_uri=%s" %
    #                  (config.AWS_COGNITO_DOMAIN, config.AWS_COGNITO_USER_POOL_CLIENT_ID,
    #                   config.AWS_COGNITO_LOGOUT_URL, session['csrf_state'],config.AWS_COGNITO_REDIRECT_URL))
    cognito_logout = ("%s/"
                      "logout?client_id=%s"
                      "&logout_uri=%s" %
                     ( config.AWS_COGNITO_DOMAIN,config.AWS_COGNITO_USER_POOL_CLIENT_ID,
                      config.AWS_COGNITO_LOGOUT_URL))
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

        cred = boto3.Session().get_credentials()

        session['iamaccess'] = cred.access_key
        session['iamsecret'] = cred.secret_key
        session['iamtoken'] = cred.token

        s3client = boto3.client('s3', 
                                aws_access_key_id = session['iamaccess'], 
                                aws_secret_access_key = session['iamsecret'], 
                                aws_session_token = session['iamtoken']
                            )

        response = s3client.get_object(Bucket='df-fin-data', Key='pickle/work.pickle')

        body = response['Body'].read()

        global work_df
        work_df = pickle.loads(body)
        print(work_df.head(5))

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

    fig = go.Figure()
    print((current_user.is_authenticated and not work_df.empty))

    if current_user.is_authenticated and not work_df.empty:

        # _df = work_df2[((work_df2['연도'] ==2021) & ( ~work_df2['금액(백만원)'].isna()))]
        _df = work_df[(( ~work_df['금액(백만원)'].isna()))]

        _df = _df.groupby(['연도','종류']).agg({'금액(백만원)':sum}).reset_index()
        _df['연도'] = _df['연도'].astype('str')

        # fig = create_table(_df, height_constant=60)

        x=_df['연도'].unique()

        fig = make_subplots(
            rows=2, cols=1,
            shared_xaxes=True,
            vertical_spacing=0.03,
            specs=[[{"type": "bar"}],
                [{"type": "table"}]]
        )

        y=_df[_df.종류=='제초제']['금액(백만원)']
        fig.add_trace(go.Bar(x=x, y=y, name='제초제',marker_color='rgb(24, 102, 225)'),row=1, col=1)
        y=_df[_df.종류=='살균제']['금액(백만원)']
        fig.add_trace(go.Bar(x=x, y=y, name='살균제',marker_color='rgb(33, 66, 171)'),row=1, col=1)
        y=_df[_df.종류=='기타약재']['금액(백만원)']
        fig.add_trace(go.Bar(x=x, y=y, name='기타약재',marker_color='navy'),row=1, col=1)

        
        fig.update_traces(textposition='auto')
        fig.update_layout(barmode='stack')

        fig.add_trace(
            go.Table(
                header=dict(values=list(_df.columns),
                    # fill_color='navy',
                    align='left'),
                cells=dict(values=[_df.연도, _df.종류,_df['금액(백만원)']],
                    # fill_color='lavender',
                    format=["g","",".1f"],
                    align='right')
            ),
            row=2, col=1
        )


        fig.update_layout(height=900)


    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    """Homepage route"""
    return render_template('home.html',  plot=graphJSON)

@application.route('/api/data')
@login_required
def data():
    # print(work_df2.head(2))
    return {'data': work_df2.to_dict('records')}

@application.route("/dswork", methods=('GET', 'POST'))
@login_required
def dswork():


    # print(work_df.head(2))
    global work_df2
    global work_df

    work_df2 = work_df[['연도', '월','일자', '조직','골프장','대분류','종류', '품목코드', '품목명[규격]', '수량', '적요', '방제단가', '금액(백만원)']]
    work_df2['방제단가'] = work_df2['방제단가'].astype(float)
    work_df2['금액(백만원)'] = work_df2['금액(백만원)'].astype(float)
    work_df2['일자'] = work_df2['일자'].dt.strftime('%Y/%m/%d')
    work_df2 = work_df2.round({'수량': 1,'방제단가':1, '금액(백만원)': 2})
    work_df2['id'] = work_df2.index +1

    work_df2 = work_df2[['id', '연도', '월','일자', '조직','골프장','대분류','종류', '품목코드', '품목명[규격]', '수량', '적요', '방제단가', '금액(백만원)']].fillna('NULL')
    work_df2.columns = ['id', '연도', '월','일자', '조직','골프장','대분류','종류', '품목코드', '품목명', '수량', '적요', '방제단가', '금액(백만원)']


    return render_template('detailtable.html', page = 'dswork')


@application.route("/dsw_freqbycourse", methods=('GET', 'POST'))
@login_required
def dswork_freqbycourse():
    # work_df = pd.read_pickle("./df_data/work.pickle") 

    sum_df1 = work_df.groupby(['조직','거래처명','골프장','연도']).agg({'일자':'nunique'})
    col = pd.MultiIndex.from_tuples([('일자', 'Total')])
    sum_df1.columns = col
    sum_df = work_df.groupby(['조직','거래처명','골프장','연도','월']).agg({'금액(백만원)':sum, '일자':'nunique'}).reindex()
    sum_df = sum_df.pivot_table(['일자'], ['조직','거래처명','골프장','연도'], '월').fillna(0)

    sum_df = pd.concat([sum_df, sum_df1] ,axis=1)

    html_out = sum_df.to_html(float_format='{:20,.1f}'.format,classes='table table-stripped table-hover')

    return render_template('simpletable.html', data = html_out, page = 'dsreport')

@application.route("/dsw_expbycourse", methods=('GET', 'POST'))
@login_required
def dswork_expbycourse():
    # work_df = pd.read_pickle("./df_data/work.pickle") 

    sum_df1 = work_df.groupby(['조직','거래처명','골프장','연도']).agg({'금액(백만원)':sum})
    col = pd.MultiIndex.from_tuples([('금액(백만원)', 'Total')])
    sum_df1.columns = col
    sum_df = work_df.groupby(['조직','거래처명','골프장','연도','월']).agg({'금액(백만원)':sum, '일자':'nunique'}).reindex()
    sum_df = sum_df.pivot_table(['금액(백만원)'], ['조직','거래처명','골프장','연도'], '월').fillna(0)

    sum_df = pd.concat([sum_df, sum_df1] ,axis=1)

    html_out = sum_df.to_html(float_format='{:20,.1f}'.format,classes='table table-stripped table-hover')

    return render_template('simpletable.html', data = html_out, page = 'dsreport')

# run the application.
if __name__ == "__main__":
    # Setting debug to True enables debug output. This line should be
    # removed before deploying a production application.
    application.debug = True
    application.run('localhost')