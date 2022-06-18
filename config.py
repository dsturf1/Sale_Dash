# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
# in compliance with the License. A copy of the License is located at
#
# https://aws.amazon.com/apache-2-0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
"Central configuration"
import os

AWS_DEFAULT_REGION = 'us-east-1'
AWS_COGNITO_DOMAIN= 'https://dsturf-login-test.auth.us-east-1.amazoncognito.com'
AWS_COGNITO_USER_POOL_ID = 'us-east-1_s7z41WH1Y'
AWS_COGNITO_USER_POOL_CLIENT_ID = '5nclqdj4j2s0grki0ad1f5ef2'
AWS_COGNITO_USER_POOL_CLIENT_SECRET = '1lmqcl8945mrpvrmmk5a6b5cpt3ti0nghp3lusgmp9tareto9lks'
AWS_COGNITO_REDIRECT_URL = 'http://localhost:5000/callback'
AWS_COGNITO_LOGOUT_URL = 'http://localhost:5000'

FLASK_SECRET = 'James is King'
