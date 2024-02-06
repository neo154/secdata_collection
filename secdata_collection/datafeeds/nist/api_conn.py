"""nist/api_conn.py

Author: neo154
Version: 0.1.0
Date Modified: 2024-02-05

Has methods that are used to pull and manage the API calls for NIST data, including means of
managing with or without a token for the API
"""

import json
from datetime import date, datetime
from logging import Logger
from time import sleep
from typing import Dict, List, Tuple

from afk.afk_logging import generate_logger
from afk.storage.models import StorageLocation

from secdata_collection.utils.api_requests import (get_resume_info,
                                                   make_request,
                                                   request_stream_to_file)

_HAS_TOKEN = False
_SLEEP_TIME = 20

_DEFAULT_LOGGER = generate_logger(__name__)


def _db_file_load_callback(file_ref: StorageLocation) -> Tuple[int, int]:
    """
    Gets the file information from raw NIST file, will get the required data points
    for the next request

    :param file_ref: StorageLocation of file to open and read for next call
    :returns: Tuple of the total results and the results in the current page
    """
    with file_ref.open('r') as open_ref:
        tmp_obj = json.load(open_ref)
    return (tmp_obj['totalResults'], tmp_obj['resultsPerPage'])

def _check_headers(headers: Dict=None) -> None:
    """
    Sets sleep time based on having an api key for the global namespace

    :param headers: Dictionary of headers or None
    :returns: None
    """
    global _HAS_TOKEN   # pylint: disable=global-statement
    global _SLEEP_TIME  # pylint: disable=global-statement
    if headers is None:
        headers = {}
    if not _HAS_TOKEN and 'apiKey' in headers:
        _HAS_TOKEN = True
        _SLEEP_TIME = 3
    if _HAS_TOKEN and 'apiKey' not in headers:
        _HAS_TOKEN = False
        _SLEEP_TIME = 6

def _get_cve(url: str, cve_id: str, headers: Dict=None, proxies: Dict=None) -> Dict:
    """
    Back end getter for cves that will ignore header check and use whatever has been set.

    :param url: String of NIST endpoint to make requests for a CVE
    :param cve_id: String of CVE to search the NIST DB for
    :param headers: Dictionary of headers, that may contain a token for the NIST API
    :param proxies: Dictionary containing proxy setting for requests
    :returns: Dictionary of CVE data from NIST, or empty dictionary
    """
    _attempt = 1
    if _attempt > 2:
        try:
            return make_request(url, params={'cveId', cve_id}, headers=headers, proxies=proxies)\
                .json()['vulnerabilities'][0]['cve']
        except:  # pylint: disable=bare-except
            _attempt += 1
            sleep(_SLEEP_TIME)
    return {}

def get_cve(url: str, cve_id: str, headers: Dict=None, proxies: Dict=None) -> Dict:
    """
    Requests for specific cve for NIST DB. This isfor single CVE entries, but it is not
    recommended to use this unless totally necessary for large scale searches or updates. I
    recommend just using the full calls for DB updates or downloads

    :param url: String of NIST endpoint to make requests for a CVE
    :param cve_id: String of CVE to search the NIST DB for
    :param headers: Dictionary of headers, that may contain a token for the NIST API
    :param proxies: Dictionary containing proxy setting for requests
    :returns: Dictionary of CVE data from NIST, or empty dictionary
    """
    _check_headers(headers)
    _get_cve(url, cve_id, headers, proxies)

def get_cves(url: str, cve_ids: List[str], headers: Dict=None, proxies: Dict=None) -> List[Dict]:
    """
    Gets multiple CVEs, would use the above get_cve but this will avoid issues with multiple

    :param url: String of NIST endpoint to make requests for a CVE
    :param cve_id: List of Strings for CVEs to search the NIST DB for
    :param headers: Dictionary of headers, that may contain a token for the NIST API
    :param proxies: Dictionary containing proxy setting for requests
    :returns: Dictionary of CVE data from NIST, or empty dictionary
    """
    _check_headers(headers)
    ret_l = []
    for cve_id in cve_ids:
        tmp_ret = _get_cve(url, cve_id, headers, proxies)
        if tmp_ret:
            ret_l.append(tmp_ret)
    return ret_l

def _get_cve_loop(url: str, files_store: StorageLocation, file_prefix: str, params: Dict,
        logger_ref: Logger, headers: Dict=None, proxies: Dict=None) -> None:
    """
    Does loop for going through eah one of the indices for a given set of requests and parameters

    :param url: String of NIST endpoint to make requests for a CVE
    :param files_store: StorageLocation of location to store these CVE files, typically tmp storage
    :param file_prefix: String of prefix for CVE download file names
    :param params: Dictionary of parameters to send for requests
    :param logger_ref: Logger object
    :param headers: Dictionary of headers, that may contain a token for the NIST API
    :param proxies: Dictionary containing proxy setting for requests
    :returns: None
    """
    start_index = 0
    params['startIndex'] = start_index
    tmp_file: StorageLocation = files_store.join_loc(f'{file_prefix}{start_index}.json')
    if tmp_file.exists():
        logger_ref.info("Attempting to resume download")
        resume_info = get_resume_info(files_store, rf'{file_prefix}[0-9]+.json',
            file_prefix, _db_file_load_callback)
        start_index = resume_info[0]
        total_results, results_per_page = resume_info[1]
    else:
        total_results, results_per_page = request_stream_to_file(url=url, dest_loc=tmp_file,
            params=params, headers=headers, request_type='GET',
            file_callback=_db_file_load_callback, proxies=proxies)
        logger_ref.debug('Total Results %d, per page %d', total_results, results_per_page)
    start_index += results_per_page
    while start_index < total_results:
        params['startIndex'] = start_index
        tmp_file = files_store.join_loc(f'{file_prefix}{start_index}.json')
        logger_ref.debug('Current position: %d out of %d', start_index, total_results)
        request_stream_to_file(url=url, dest_loc=tmp_file, params=params, headers=headers,
            request_type='GET', proxies=proxies)
        start_index += results_per_page
        sleep(_SLEEP_TIME)

def get_nist_cves_update(url: str, files_store: StorageLocation, headers: Dict=None,
        last_mod_datetime: datetime=None, logger_ref: Logger=_DEFAULT_LOGGER,
        proxies: Dict=None) -> None:
    """
    Gets NIST CVEs that have been updated after a given last modification date, typically
    originating from a locally storeddata

    :param url: String of NIST endpoint to make requests for a CVE
    :param files_store: StorageLocation of location to store these CVE files, typically tmp storage
    :param headers: Dictionary of headers, that may contain a token for the NIST API
    :param last_mod_datetime: Datetime object of when NIST data was last modified from local data
    :param logger_ref: Logger object
    :param proxies: Dictionary containing proxy setting for requests
    :returns: None
    """
    if not files_store.is_dir():
        raise ValueError("Temporary area to store response files for bulk NIST pulls is not a dir")
    _check_headers(headers)
    today_str = date.today().strftime("%Y_%m_%d")
    file_prefix = f'nist_cves_init_db_{today_str}_'
    params = {}
    if last_mod_datetime is not None:
        file_prefix = f'nist_cve_inc_{today_str}_'
        params['lastModStartDate'] = last_mod_datetime.strftime('%Y-%m-%dT%H:%M:%SZ')
        params['lastModEndDate'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    _get_cve_loop(url, files_store, file_prefix, params, logger_ref, headers, proxies)

def get_nist_full_datafiles(url: str, files_store: StorageLocation, headers: Dict=None,
        logger_ref: Logger=_DEFAULT_LOGGER, proxies: Dict=None) -> None:
    """
    Gets full list of nist CVEs for base datafiles from the entire NIST API

    :param url: String of NIST endpoint to make requests for a CVE
    :param files_store: StorageLocation of location to store these CVE files, typically tmp storage
    :param headers: Dictionary of headers, that may contain a token for the NIST API
    :param logger_ref: Logger object
    :param proxies: Dictionary containing proxy setting for requests
    :returns: None
    """
    if not files_store.is_dir():
        raise ValueError("Temporary area to store response files for bulk NIST pulls is not a dir")
    _check_headers(headers)
    today_str = date.today().strftime("%Y_%m_%d")
    file_prefix = f'nist_cves_full_{today_str}_'
    _get_cve_loop(url, files_store, file_prefix, {}, logger_ref, headers, proxies)
