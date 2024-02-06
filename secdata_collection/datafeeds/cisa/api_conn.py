"""cisa/api_conn.py

Author: neo154
Version: 0.1.0
Date Modified: 2024-02-05

Methods that are used to make calls to the API connection and organize the data pulled
from CISA for their KEV CVE collection
"""

from typing import Any, Dict

from afk import StorageLocation

from secdata_collection.utils import (_StreamFileCallback,
                                      request_stream_to_file)


def get_cisa_kev(url: str, dest_loc: StorageLocation, proxies: Dict=None,
        file_callback: _StreamFileCallback=None) -> Any:
    """
    CISA KEV download

    :param url: String of URL endpoint for getting KEV catalogue in CSV form
    :param dest_loc: StorageLocation of where CSV data is stored as a file
    :param proxies: Dictionary of proxy entries
    :param file_callback: Callback function to run if one is required
    :returns: None or results from file_callback
    """
    return request_stream_to_file(url=url, dest_loc=dest_loc, proxies=proxies,
        file_callback=file_callback)
