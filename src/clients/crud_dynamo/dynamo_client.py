import os
import logging

DEBUG_MODE = os.environ['DEBUG_MODE']
API_VERSION = 'v1'


# Configure logger
logger = logging.getLogger(__name__)


def create_ddb_object(table, item):
    return table.put_item(
        Item={item}
    )


def read_ddb_object(table, key):
    r = table.get_item(
        Key={key}
    )
    item = r['Item'] #ddb returns a key Item whose contains our response

    return item


def update_ddb_object(table, key):
    r = table.update_item(
        Key={key}
    )
    item = r['Item']
    return item


def delete_ddb_object(table, key):
    table.delete_item(
        Key={key}
    )

