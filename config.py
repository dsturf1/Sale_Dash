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

AWS_DEFAULT_REGION = os.environ['AWS_DEFAULT_REGION']
AWS_COGNITO_DOMAIN = os.environ['AWS_COGNITO_DOMAIN']
AWS_COGNITO_USER_POOL_ID = os.environ['AWS_COGNITO_USER_POOL_ID']
AWS_COGNITO_USER_POOL_CLIENT_ID = os.environ['AWS_COGNITO_USER_POOL_CLIENT_ID']
AWS_COGNITO_USER_POOL_CLIENT_SECRET = os.environ['AWS_COGNITO_USER_POOL_CLIENT_SECRET']
AWS_COGNITO_REDIRECT_URL = os.environ['AWS_COGNITO_REDIRECT_URL']
AWS_COGNITO_LOGOUT_URL = os.environ['AWS_COGNITO_LOGOUT_URL']

FLASK_SECRET = os.environ['FLASK_SECRET']