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
    html_out = []


    if current_user.is_authenticated:
        s3client = boto3.client('s3', 
                            aws_access_key_id = session['iamaccess'], 
                            aws_secret_access_key = session['iamsecret'], 
                            aws_session_token = session['iamtoken']
                        )

        response = s3client.get_object(Bucket='df-fin-data', Key='pickle/MonthlySale2022.pickle')
        body = response['Body'].read()
        _df = pickle.loads(body)

        response = s3client.get_object(Bucket='df-fin-data', Key='data_template/MonthlySale2022.html')
        html_out = response['Body'].read().decode('utf-8')

        fig.update_layout(
            # template="simple_white",
            xaxis=dict(title_text="월"),
            yaxis=dict(title_text="금액"),
            barmode="stack",
            template="simple_white"
        )

        colors = [["#000080", "#1866E1"],["#FAE500", "#FFF7A7"]]


        for r, c in zip(_df.구분.unique(), colors):
            plot_df = _df[_df.구분 == r]
            fig.add_trace(
                go.Bar(x=[plot_df.월, plot_df.연도], y=plot_df.Value, name=r, marker_color=c*12),
            )
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    """Homepage route"""
    return render_template('home.html',  plot= graphJSON, data = html_out)

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
    s3client = boto3.client('s3', 
                        aws_access_key_id = session['iamaccess'], 
                        aws_secret_access_key = session['iamsecret'], 
                        aws_session_token = session['iamtoken']
                    )

    response = s3client.get_object(Bucket='df-fin-data', Key='pickle/SaleByProduct2021.pickle')
    body = response['Body'].read()
    _df1 = pickle.loads(body)

    response = s3client.get_object(Bucket='df-fin-data', Key='pickle/SaleByProduct2022.pickle')
    body = response['Body'].read()
    _df2 = pickle.loads(body)

    response = s3client.get_object(Bucket='df-fin-data', Key='data_template/SaleByProduct2021.html')
    html_out1 = response['Body'].read().decode('utf-8')

    response = s3client.get_object(Bucket='df-fin-data', Key='data_template/SaleByProduct2022.html')
    html_out2 = response['Body'].read().decode('utf-8')


    fig = make_subplots(
                rows=1, cols=2,
                vertical_spacing=0.03,
                subplot_titles=['2022','2021']
                
                # specs=[[{"type": "bar"}],
                #     [{"type": "bar"}]]
            )
    fig.add_trace(go.Bar(
        y=_df2['품목명'],
        x=_df2['비용'],
        name='원가',
        orientation='h',
        marker=dict(
            color='#000080',
            # line=dict(color='"#000080', width=3)
        )

    )    ,row=1, col=1)
    fig.add_trace(go.Bar(
        y=_df2['품목명'],
        x=_df2['이익'],
        name='마진',
        orientation='h',
        marker=dict(
            color='#1866E1',
            # line=dict(color='"#000080', width=3)
        )

    )    ,row=1, col=1)

    # fig.update_layout(barmode='stack', height=700)

    fig.add_trace(go.Bar(
        y=_df1['품목명'],
        x=_df1['비용'],
        name='원가',
        orientation='h',
        marker=dict(
            color='#000080',
            # line=dict(color='"#000080', width=3)
        )

    )    ,row=1, col=2)
    fig.add_trace(go.Bar(
        y=_df1['품목명'],
        x=_df1['이익'],
        name='마진',
        orientation='h',
        marker=dict(
            color='#1866E1',
            # line=dict(color='"#000080', width=3)
        )
    )    ,row=1, col=2)

    fig.update_layout(barmode='stack', height=700,     template="simple_white")

    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template('twoTable.html',  plot= graphJSON, data1 = html_out1, data2 = html_out2, page = 'dsreport')

@application.route("/dsw_expbycourse", methods=('GET', 'POST'))
@login_required
def dswork_expbycourse():
    s3client = boto3.client('s3', 
                        aws_access_key_id = session['iamaccess'], 
                        aws_secret_access_key = session['iamsecret'], 
                        aws_session_token = session['iamtoken']
                    )

    response = s3client.get_object(Bucket='df-fin-data', Key='pickle/SaleByClient2021.pickle')
    body = response['Body'].read()
    _df1 = pickle.loads(body)

    response = s3client.get_object(Bucket='df-fin-data', Key='pickle/SaleByClient2022.pickle')
    body = response['Body'].read()
    _df2 = pickle.loads(body)

    response = s3client.get_object(Bucket='df-fin-data', Key='data_template/SaleByClient2021.html')
    html_out1 = response['Body'].read().decode('utf-8')

    response = s3client.get_object(Bucket='df-fin-data', Key='data_template/SaleByClient2022.html')
    html_out2 = response['Body'].read().decode('utf-8')


    fig = make_subplots(
            rows=1, cols=2,
            vertical_spacing=0.03,
            subplot_titles=['2022','2021']
            
            # specs=[[{"type": "bar"}],
            #     [{"type": "bar"}]]
        )
    fig.add_trace(go.Bar(
        y=_df2['거래처명'],
        x=_df2['비용'],
        name='원가',
        orientation='h',
        marker=dict(
            color='#000080',
            # line=dict(color='"#000080', width=3)
        )

    )    ,row=1, col=1)
    fig.add_trace(go.Bar(
        y=_df2['거래처명'],
        x=_df2['이익'],
        name='마진',
        orientation='h',
        marker=dict(
            color='#1866E1',
            # line=dict(color='"#000080', width=3)
        )

    )    ,row=1, col=1)

    # fig.update_layout(barmode='stack', height=700)

    fig.add_trace(go.Bar(
        y=_df1['거래처명'],
        x=_df1['비용'],
        name='원가',
        orientation='h',
        marker=dict(
            color='#000080',
            # line=dict(color='"#000080', width=3)
        )

    )    ,row=1, col=2)
    fig.add_trace(go.Bar(
        y=_df1['거래처명'],
        x=_df1['이익'],
        name='마진',
        orientation='h',
        marker=dict(
            color='#1866E1',
            # line=dict(color='"#000080', width=3)
        )
    )    ,row=1, col=2)

    fig.update_layout(barmode='stack', height=700,     template="simple_white")

    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template('twoTable.html',  plot= graphJSON, data1 = html_out1, data2 = html_out2, page = 'dsreport')

# run the application.
if __name__ == "__main__":
    # Setting debug to True enables debug output. This line should be
    # removed before deploying a production application.
    application.debug = True
    application.run('localhost')