import json
import datetime

from http import cookies


class ApiGatewayRequest(object):

    def __init__(self, event, context=None):
        """
        ApiGateway lambda_proxy integration request model
        :param event:
        :type event: dict
        """
        if not ApiGatewayRequest.is_api_gateway_request(event):
            raise Exception("event object is not an ApiGateway lambda proxy integration request data")

        self.http_method = event.get('httpMethod')  # GET
        self.path = event.get('path')  # /v1/files
        self.resource = event.get('resource')  # /v1/files/{path_param}

        self.path_parameters = event.get('pathParameters')  # { "Key": "value" }
        self.query_string_parameters = event.get('queryStringParameters')  # query_parameters
        self.headers = event.get('headers')  # ^

        if self.headers is not None and 'Cookie' in self.headers:
            self.cookie = ApiGatewayRequest.parse_cookie(event['headers']['Cookie'])
        else:
            self.cookie = None

        # self.body = event.get('body')
        self.body = json.loads(event['body']) if event['body'] else {}
        self.domain_name = event['requestContext']['domainName']  # abc.execute-api.eu-central-1.amazonaws.com
        self.authorizer = event['requestContext']['authorizer'] if 'authorizer' in event['requestContext'] else None

    @staticmethod
    def parse_cookie(cookie_str):
        """
        Parse HTTP "Cookie" header string
        :rtype: dict
        """
        # prevent "AttributeError: 'unicode' object has no attribute 'items'"
        if isinstance(cookie_str, str):
            cookie_str = cookie_str.encode("utf8")

        parsed_cookies = {}

        cookie = cookies.SimpleCookie("Cookie: %s" % cookie_str)
        for key, morsel in cookie.items():
            parsed_cookies[key] = {}
            parsed_cookies[key]['value'] = morsel.value
            for attr, value in morsel.items():
                parsed_cookies[key][attr] = value

        return parsed_cookies

    @staticmethod
    def get_cookie_expires(days=0, hours=1, minutes=0):
        """
        :param days: number of days in the future
        :param hours: number of hours in the future
        :param minutes: number of minutes in the future
        :type days: int
        :type hours: int
        :type minutes: int
        :return: 'Tue, 15 Jan 2013 21:47:38 GMT'
        :rtype: str
        https://stackoverflow.com/questions/6556930/python-persistent-cookie-generate-expires-field
        """
        expires = datetime.datetime.now() + datetime.timedelta(days=days, hours=hours, minutes=minutes)
        return expires.strftime('%a, %d %b %Y %H:%M:%S')

    @staticmethod
    def is_api_gateway_request(event):
        return bool(event) and 'httpMethod' in event

