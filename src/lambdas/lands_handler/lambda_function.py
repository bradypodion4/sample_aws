import uuid
import os
import logging
import boto3
from crud_dynamo import dynamo_client
from api_gateway.request import ApiGatewayRequest
from api_gateway.response import ApiGatewayResponse

DEBUG_MODE = os.environ['DEBUG_MODE']
API_VERSION = 'v1'
ddb = boto3.resource('dynamodb')
table = ddb.Table('lands')

# Configure logger
logger = logging.getLogger(__name__)




def lambda_handler(event, context):
    try:
        logger.debug(f'Received event: {event}\n Received context: {context}')
        api_request = ApiGatewayRequest(event, context)
        api_response = api_resource_strategy_dict.get(api_request.resource, api_default_handler)(api_request)
        logger.debug(api_response)
        return ApiGatewayResponse(status_code=ApiGatewayResponse.HTTP_STATUS_OK, body=api_response).build()

    except Exception as e:
        logger.exception(e)
        return ApiGatewayResponse(ApiGatewayResponse.HTTP_STATUS_FORBIDDEN, {"errorMsg": str(e)}).build()


def api_default_handler(api_request):
    """
    raise exceptions when resources or methods aren't recognized
    :param api_request:
    :type api_request: ApiGatewayRequest
    :return:
    """
    try:
        logger.info('entering default handler')
        logger.debug(f'api_request: {api_request}')
    except Exception as e:
        logger.error(f'Unsupported resource or method in {api_request}\n Exception: {e}')


def create(api_request):
    body = api_request.body
    return dynamo_client.create_ddb_object(table, body)


def read(api_request):
    body = api_request.body
    return dynamo_client.read_ddb_object(table, body)


def update(api_request):
    body = api_request.body
    return dynamo_client.update_ddb_object(table, body)


def delete(api_request):
    path_params = api_request.path_parameters
    return dynamo_client.delete_ddb_object(table, path_params)


api_resource_strategy_dict = {
    f'{API_VERSION}/lands': lambda request: api_buckets_actions_resource_handler_dict.get(request.http_method)(request),
    f'{API_VERSION}/lands/create': lambda request: api_buckets_actions_resource_handler_dict.get(request.http_method)(request),
    f'{API_VERSION}/lands/update': lambda request: api_buckets_actions_resource_handler_dict.get(request.http_method)(request),
    f'{API_VERSION}/lands/delete': lambda request: api_buckets_actions_resource_handler_dict.get(request.http_method)(request),
}


api_buckets_actions_resource_handler_dict = {
    'GET': read,
    'POST': create,
    'PATCH': update,
    'DELETE': delete,
}
