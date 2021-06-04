import datetime
import decimal
import json
import logging

logger = logging.getLogger(__name__)


class ApiGatewayResponse(object):
    """
    ApiGateway lambda proxy integration response model
    """

    HTTP_STATUS_OK = 200  # The request has succeeded.
    HTTP_STATUS_CREATED = 201  # The request has succeeded and a new resource has been created.
    HTTP_STATUS_ACCEPTED = 202  # The request has been received but not yet acted upon.
    HTTP_STATUS_NO_CONTENT = 204  # There is no content to send for this request, but the headers may be useful.
    HTTP_STATUS_MOVED_PERMANENTLY = 301  # Means that the URI of the requested resource has been changed permanently.
    HTTP_STATUS_BAD_REQUEST = 400  # Means that server could not understand the request due to invalid syntax.
    HTTP_STATUS_UNAUTHORIZED = 401  # The client must authenticate itself to get the requested response.
    HTTP_STATUS_FORBIDDEN = 403  # The client does not have access rights to the content, i.e. they are unauthorized.
    HTTP_STATUS_NOT_FOUND = 404  # The server can not find requested resource.
    HTTP_STATUS_INTERNAL_SERVER_ERROR = 500  # The server has encountered a situation it doesn't know how to handle.
    HTTP_STATUS_NOT_IMPLEMENTED = 501  # The request method is not supported by the server and cannot be handled.
    HTTP_STATUS_SERVICE_UNAVAILABLE = 503  # The server is not ready to handle the request.

    HTTP_DEFAULT_HEADERS = {
        'Content-Type':                       'application/json',
        'Access-Control-Allow-Origin':        '*',                  # If you're making a credentialed request, the wildcard value is not allowed
        # 'Access-Control-Allow-Headers':     'Authorization',      # Not required
        # 'Access-Control-Allow-Credentials': True                  # Required for credentialed requests (cookies, authorization headers, TLS client certificates)
    }

#TODO think headers in another way, argument is mutable
    def __init__(self, status_code, body=None, error=None, headers=HTTP_DEFAULT_HEADERS,
                 multi_value_headers=None,
                 is_base64_encoded=False
                 ):
        """
        :param status_code:
        :type status_code:
        :param body: a json dumpable object
        :type body: dict
        :param headers:
        :type headers: dict
        :param multi_value_headers:
        :type multi_value_headers: dict
        :param is_base64_encoded:
        :type is_base64_encoded: bool
        :raise: NotJsonDumpableObjectException
        """
        self.status_code = status_code

        if error is not None:
            self.body = {
                "message": repr(error.message).replace('\n', ''),
                "code": self.status_code,
                "errors": [x.replace('\n', '') for x in error.err_stack]
            }
        else:
            self.body = body

        self.headers = headers
        self.is_base64Encoded = is_base64_encoded
        self.multi_value_headers = multi_value_headers

    def build(self):
        """
        Build the response object in the format expected by ApiGateway using lambda proxy integration.
        :return: response
        :rtype: dict
        """
        response = {
            'statusCode': self.status_code,
            'body': self.body,
            'headers': self.headers,
            'multiValueHeaders': self.multi_value_headers,
            'isBase64Encoded': self.is_base64Encoded,
        }
        logger.debug(f'Built Response: {json.dumps(response)}')

        return response

    @staticmethod
    def _validate_body(body):
        """

        :param body:
        :return: NotJsonDumpableObjectException
        """
        if body is not None and not isinstance(body, JsonDumpableObject):
            raise Exception(f'Object type: {type(body)} is not json dumpable')

    @staticmethod
    def custom_json_decoder(obj):
        if isinstance(obj, decimal.Decimal):
            return int(obj)
        elif isinstance(obj, datetime.datetime):
            return obj.strftime("%Y/%m/%d-%H:%M:%S")
        else:
            logger.warning(f"Unexpected type {type(obj)}")
            logger.warning("For object: %r", obj)
        raise TypeError("Invalid type in response body")


class JsonDumpableObject(object):
    def to_json_dumpable_representation(self):
        pass