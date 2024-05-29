"""api_requests.py

Author: neo154
Version: 0.1.1
Date Modified: 2024-04-09

This is the module that is responsible for wrapping and handling api requests from the various
modules and can handle the repsonses to get the returns or raw return data
"""

import re
from time import sleep
from typing import Any, Callable, Dict, List, Union, Tuple, Literal

import requests
import urllib3
from afk import StorageLocation

_VERIFY = True

_StreamFileCallback = Callable[[StorageLocation], Any]
_FileIntegrityCallable = Callable[[StorageLocation], None]
_ResumeRequestsCallback = Callable[[StorageLocation], Any]
_RequestCallback = Callable[[requests.Response], Any]
_RequestType = Literal['GET', 'POST', 'DELETE', 'HEAD', 'PUT', 'PATCH', 'OPTIONS']

def disable_request_verification() -> None:
    """
    Use only if there's decyprtion endpoints in your environment, like from a private network to
    internet, otherwise MiTM would be possible
    Will set verification for requests to false globally for instance and suppress URLlib3 warnings

    :returns: None
    """
    global _VERIFY  # pylint: disable=global-statement
    _VERIFY = False
    urllib3.disable_warnings()

def make_request(url: str, params: Dict=None, headers: Dict=None, data: Dict=None,
        json_obj: Dict=None, request_type: _RequestType='GET',
        auth: requests.models.HTTPBasicAuth=None, files: Dict=None,
        stream: bool=False, encoding:str=None, proxies: Dict=None, accept_codes: List[int]=None,
        timeout:int=None, allowed_attempts: int=3,
        request_callback: _RequestCallback=None) -> Union[requests.Response, Any]:
    """
    Provides raw requests responses but will handle common errors or issues that require retries
    or special handling from a calling function

    :param url: String of endpoint to send a request to
    :param params: Dictionary of parameters for request
    :param headers: Dictionary of headers for request
    :param data: Dictionary of data for body for request
    :param json_obj: Dictinoary object as JSON for request
    :param request_type: String of type of request to be sent
    :param auth: HTTPBasicAuth object for requests that use basic auth only
    :param files: Dictionary of file information for request
    :param stream: Boolean indicating whetheror not response is streaming or not
    :param endcoding: String identifying the type of encoding the request needs to be in
    :param proxies: Dictionary of proxy settings for request
    :param accept_codes: List of integers for response codes that need to return other than 200
    :param timeout: Integer of amount of seconds to wait until a timeout occurs for request
    :param allowed_attempts: Integer of number of attempts before an acceptable code response
    :param request_callback: Callable for some function to use response and return some data
    :returns: Response, if request_callback is provided can be any
    """
    if accept_codes is None:
        accept_codes = []
    attempt = 0
    while attempt < allowed_attempts:
        attempt += 1
        response = requests.request(method=request_type, url=url, proxies=proxies, params=params,
            data=data, headers=headers, files=files, auth=auth, json=json_obj, stream=stream,
            timeout=timeout, verify=_VERIFY)
    if response.ok or response.status_code in [accept_codes]:
        if not encoding is None:
            response.encoding = encoding
        if request_callback is not None:
            return request_callback(response)
        return response
    if response.status_code==429:
        sleep(5)
    response.raise_for_status()

def request_stream_to_file(url: str, dest_loc: StorageLocation, params: Dict=None,
        headers: Dict=None, data: Dict=None, json_obj: Dict=None, request_type: str='GET',
        auth: requests.models.HTTPBasicAuth=None, encoding:str=None, proxies: Dict=None,
        timeout:int=None, allowed_attempts: int=3, chunk_size: int=4096,
        file_callback: _StreamFileCallback=None,
        integrity_check_callable: _FileIntegrityCallable=None, **kwargs) -> Union[Any, None]:
    """
    Requests that streams results directly to file from the request if ther wa a good status code

    :param url: String of endpoint to send a request to
    :param dest_loc: StorageLocation to store the resulting contents of request response
    :param params: Dictionary of parameters for request
    :param headers: Dictionary of headers for request
    :param data: Dictionary of data for body for request
    :param json_obj: Dictinoary object as JSON for request
    :param request_type: String of type of request to be sent
    :param auth: HTTPBasicAuth object for requests that use basic auth only
    :param endcoding: String identifying the type of encoding the request needs to be in
    :param proxies: Dictionary of proxy settings for request
    :param accept_codes: List of integers for response codes that need to return other than 200
    :param timeout: Integer of amount of seconds to wait until a timeout occurs for request
    :param allowed_attempts: Integer of number of attempts before an acceptable code response
    :param chunk_size: Integer for number of bytes for each chunk in response processing
    :param file_callback: Callable for some function to use response and return some data
    :param integrity_check_callable: Callable for some function to do integrity check of file
    :param **kwargs: Dictionary reference of any other values for file_callback call
    :returns: Response, if request_callback is provided can be any
    """
    attempt = 0
    while attempt < allowed_attempts:
        try:
            with make_request(url=url, params=params, headers=headers, data=data, json_obj=json_obj,
                    request_type=request_type, encoding=encoding, proxies=proxies, auth=auth,
                    timeout=timeout, stream=True) as stream_response:
                if stream_response.status_code==200:
                    with dest_loc.open('wb') as open_dest:
                        for chunk in stream_response.iter_content(chunk_size=chunk_size):
                            _ = open_dest.write(chunk)
                    if integrity_check_callable is not None:
                        integrity_check_callable(dest_loc)
                    if file_callback is not None:
                        return file_callback(dest_loc, **kwargs)
                    return
        except Exception as exc:  # pylint: disable=broad-exception-caught
            attempt += 1
            if attempt > allowed_attempts:
                raise RuntimeError("Number of allowed attempts to download file") from exc

def get_ordered_storage_names(storage_loc: StorageLocation, file_pattern: str,
        file_prefix: str) -> Dict[int, StorageLocation]:
    """
    Gets ordered storage locations in a resulting dictionary for some number, for page
    or other type of indexing, and the StorageLocation

    :param storage_loc: StorageLocation of where these files are stored
    :param file_pattern: String of filenames, like prefix or regex pattern for file identification
    :param file_prefix: String of file prefix to use for splitting for indexer references
    :returns: Dictionary of Storage locations with an ordered index
    """
    if not storage_loc.is_dir():
        raise ValueError("Cannot list items in a non-dir storage location")
    file_dict = {}
    storage_item: StorageLocation
    for storage_item in storage_loc.iter_location():
        if re.match(file_pattern, storage_item.name) is not None:
            indexer = storage_item.name.split('.')[0].replace(file_prefix, '')
            try:
                int_index = int(indexer)
                file_dict[int_index] = storage_item
            except ValueError as v_error:
                raise ValueError(f'Cannot locate int for indexer value with {storage_item.name}"\
                    f" using prefix {file_prefix}') from v_error
    return dict(sorted(file_dict.items()))

def get_resume_info(storage_loc: StorageLocation, file_pattern: str, file_prefix: str,
        resume_callback: _ResumeRequestsCallback, **kwrags) -> Union[Tuple[int, ...], None]:
    """
    Gets resuming information from request file callbacks that are used to get necessary info
    for the next request. Gives back information for indexer and any other required info for
    next request if one is present

    :param storage_loc: StorageLocation of where these files are stored
    :param file_pattern: String of filenames, like prefix or regex pattern for file identification
    :param file_prefix: String of file prefix to use for splitting for indexer references
    :param resume_callback: Callback used to pull info for following requests
    :returns: None if requests are finished or Tuple info for index and any other data for request
    """
    ordered_files = get_ordered_storage_names(storage_loc, file_pattern, file_prefix)
    prev_value = ()
    for index, storage_item in ordered_files.items():
        try:
            prev_value = (index, resume_callback(storage_item, **kwrags))
        except:  # pylint:disable=bare-except
            # This triggers if a file has been corrupted giving info on the last request
            return prev_value
    return prev_value
