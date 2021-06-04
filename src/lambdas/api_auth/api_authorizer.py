import os
import json
import logging
from jose import jwt, jwk
from jose.utils import base64url_decode
from jose.exceptions import JWTError, JWTSignatureError, ExpiredSignatureError
from urllib.request import urlopen
from policy import AuthPolicy, HttpVerb

# Global parameters

# ENV = os.environ['ENV']
DEBUG_MODE = os.environ['DEBUG_MODE'].lower() == 'true'
USER_POOL_ID = os.environ['TRUSTED_USER_POOL_ID']
USER_POOL_REGION = os.environ['TRUSTED_USER_POOL_REGION']
USER_POOL_KEYS_CACHE = {}

USER_POOL_KEYS_URL = f'https://cognito-idp.{USER_POOL_REGION}.amazonaws.com/{USER_POOL_ID}/.well-known/jwks.json'
USER_POOL_GROUP_ADMIN = 'first_user_group'

# Configure logging
logger = logging.getLogger(__name__)

if DEBUG_MODE:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)


# ============================================================================================================
# lambda_handler
# ============================================================================================================


def lambda_handler(event, context):
    logger.debug(f'Received event: {json.dumps(event, indent=2)}')
    try:
        return _authorize_request(event, context)
    except (JWTError, JWTSignatureError, ExpiredSignatureError) as e:
        logger.error(f'Forbidden: {str(e)}',)
        return _create_auth_policy(event, None, e)
    except Exception as e:
        logger.error(f'Exception: {str(e)}')
        raise e


# ============================================================================================================
# TODO REFACTOR
# ============================================================================================================

def _authorize_request(event, context):
    """
    - validates the provided token in the request
    - if is valid
      - it creates the IAM Policy to authorize the authenticated user
    - if something goes wrong during the workflow it
      denies the access to the API resources

    :param event:
    :param context:
    :return: auth_policy
    :rtype: AuthPolicy - an IAM Policy
    """
    # Extracts client token from the request
    client_token = _get_client_token(event)

    # Decodes client token
    decoded_token = _decode_client_token(client_token)

    # Validates client token
    _validates_client_token(
        client_token,
        decoded_token,
    )

    # Creates policy for the authenticated user
    auth_policy = _create_auth_policy(event, decoded_token)

    # Creates context for the authenticated user
    user_context = _create_user_context(decoded_token)

    # Creates authentication response
    auth_response = auth_policy
    auth_response['context'] = user_context
    logger.debug(f'Authorization response: {json.dumps(auth_response, indent=2)}')
    return auth_response


def _get_client_token(event):
    """
    Extracts client token from the request

    :param event:
    :return: client_token
    :rtype: str
    """
    if 'authorizationToken' in event:
        authorization_header = event.get('authorizationToken')

        token_prefix = 'Bearer '
        if not authorization_header.startswith(token_prefix):
            logger.error('Bad authorizationToken, it should start with "Bearer "')
            raise Exception('Bad authorizationToken, it should start with "Bearer "')

        client_token = authorization_header[len(token_prefix):]
    elif 'queryStringParameters' in event and 'token' in event.get('queryStringParameters'):
        client_token = event['queryStringParameters'].get('token')
    else:
        logger.error('Missing authorization token')
        raise Exception('Missing authorization token')

    logger.debug(f'Client token: {client_token}')

    return client_token


def _decode_client_token(client_token):
    """
    Extracts the JWT tokens and decodes its

    :param client_token: a JWT token
    :type client_token: str
    :return: decoded_token
    {
        headers: {
            ...
        },
        claims: {
            ...
        },
        signature: str
    }
    :rtype: dict
    """
    decoded_token = {
        'headers': jwt.get_unverified_headers(client_token),
        'claims': jwt.get_unverified_claims(client_token),
        'signature': client_token.split('.')[2],
    }
    logger.debug(f'Decoded token: {json.dumps(decoded_token, indent=2)}')
    return decoded_token


def _validates_client_token(client_token, decoded_token):
    """
    It has to execute the following validations
    - verify signature
    - verify timestamp

    :param client_token:
    :param decoded_token:
    :return:
    """
    _validates_client_token_signature(client_token, decoded_token)
    _validates_client_token_expiration(client_token)
    logger.debug('Valid client token')


def _validates_client_token_signature(client_token, decoded_token):
    """
    It validates the signature of the provided token

    :param client_token:
    :param decoded_token:
    :return:
    """
    # Gets public key
    jwt_public_key = _get_jwt_public_key(decoded_token)
    # Constructs JWK key
    jwk_key = jwk.construct(jwt_public_key)

    # Extracts the section of the token to verify
    # and its signature
    encoded_section_to_verify, encoded_signature = client_token.rsplit('.', 1)
    section_to_verify = encoded_section_to_verify.encode('utf-8')
    signature = base64url_decode(encoded_signature.encode('utf-8'))

    # Verify the signature
    valid_signature = jwk_key.verify(
        section_to_verify,
        signature,
    )
    if not valid_signature:
        logger.error('Signature verification failed')
        raise JWTSignatureError('Signature verification failed')
    else:
        logger.info('Signature verified successfully')


def _get_jwt_public_key(decoded_token):
    """
    It retrieves the correct public key of the trusted user pool
    to validate the JWT.

    The trusted user pool public keys are availble at the following url:
    - https://cognito-idp.{region}.amazonaws.com/{trusted_userpool_id}/.well-known/jwks.json

    To retrieve the correct key (among all the keys of the trusted user pool), the key
    id contained in the JWT is used.

    NOTE: this method implemets a cache logic => initially the key is searched inside
    the local cache, if a miss occurs then a download from the above mentioned link
    is executed.

    :param decoded_token: decoded_token
    {
        headers: {
            'kid': the key id
        },
        claims: {
            ...
        },
        signature: str
    }
    :type decoded_token: dict
    :return: public_key to use to verify provided token
    {
        "alg":"RS256",
        "e":"A...",
        "kid":"3SR...",
        "kty":"RSA",
        "n":"t9n-7cz8MEFny...",
        "use":"sig"
    }
    :rtype: dict
    """
    key_id = decoded_token['headers']['kid']

    # Checks if the key is already cached
    key = USER_POOL_KEYS_CACHE.get(key_id)

    if key is None:
        # CACHE MISS: Downloads the key
        logger.debug(f'USER_POOL_KEYS_URL: {USER_POOL_KEYS_URL}')
        response = urlopen(USER_POOL_KEYS_URL)

        response_obj = json.loads(response.read())
        logger.debug(json.dumps(response_obj, indent=2))

        response_keys = response_obj['keys']

        logger.debug(f'Retrieved keys from url {USER_POOL_KEYS_URL}:\n{json.dumps(response_keys, indent=2)}')
        for response_key in response_keys:
            if response_key['kid'] == key_id:
                key = response_key
                USER_POOL_KEYS_CACHE[key_id] = key
                break

    # Checks if now key has been retrieved
    if key is None:
        logger.error(f'Can\'t find UserPool public key with id: {key_id}')
        raise JWTError('Can\'t find matching UserPool public key')

    logger.debug(
        'Public key found: %s',
        json.dumps(key, indent=2),
    )
    return key


def _validates_client_token_expiration(client_token):
    """
    It validates that the token is not expired

    :param client_token:
    :return:
    """
    try:
        jwt.decode(
            token=client_token,
            # note: key's expiration does not need to be checked
            key='no-key',
            options={
                'verify_nbf': False,
                'verify_iss': False,
                'verify_signature': False,
                'leeway': 0,
                'verify_sub': False,
                'verify_jti': False,
                'verify_exp': True,
                'verify_iat': False,
                'verify_at_hash': False,
                'verify_aud': False
            },
        )
    except ExpiredSignatureError as e:
        raise e

    logger.debug('Token not expired')


def _create_auth_policy(event, decoded_token, exception=None):
    """
    Creates a policy to allow access to selected resources
    :param event:
    :param decoded_token:
    :param exception:
    :return: iam policy
    :rtype: AuthPolicy
    """

    # Extracts the base information from the event
    method_arn_elements = event['methodArn'].split(':')
    api_gateway_arn_elements = method_arn_elements[5].split('/')
    aws_account_id = method_arn_elements[4]

    # Extracts the base information from the user token (can be None if exception occurred)
    if decoded_token is not None and 'claims' in decoded_token:
        cognito_username = decoded_token['claims']['cognito:username'] if 'cognito:username' in decoded_token['claims'] else "missingCognitoUsernameInToken"
        cognito_groups = decoded_token['claims'].get('cognito:groups', [])
    else:
        cognito_username = "errorDecodingToken"
        cognito_groups = []

    # Initializes the authorization policy
    policy = AuthPolicy(principal=cognito_username, aws_account_id=aws_account_id)
    policy.rest_api_id = api_gateway_arn_elements[0]
    policy.region = method_arn_elements[3]
    policy.stage = api_gateway_arn_elements[1]

    # Deny all methods if exception occurred
    if exception is not None:
        policy.deny_all_methods()
        return policy.build()

    # ADMIN permissions - allow all TODO create Admin-Group
    if USER_POOL_GROUP_ADMIN in cognito_groups:
        policy.allow_method(HttpVerb.ALL, '/*')

    return policy.build()

