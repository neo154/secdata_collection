"""github/api_conn.py

Author: neo154
Version: 0.1.0
Date Modified: 2024-05-27

Module containing the API connection information for GitHub Security Advisories
for pulling the full set of data for GHSA and related vuln mapping and information
"""

import json
from typing import Dict, Tuple
from datetime import datetime

from afk import StorageLocation

from secdata_collection.datafeeds.github.gql_queries import (GH_VULN_GQL, GHSA_GQL)
from secdata_collection.utils.api_requests import get_resume_info, request_stream_to_file

_DEFAULT_GITHUB_GQL_URL = ""

def _response_integrity_check(response_obj: Dict) -> None:
    """
    Checks for response integiryt of GQL requests and returns value errors if there's
    and integrity issue

    :param response_obj: Dictionary response object response from API call
    :returns: None
    :raises: ValueError if GQL error occured but response was still successful
    """
    if 'errors' in response_obj:
        raise ValueError("Response had a error")

def _get_next_request_info(response_json: StorageLocation,
        ret_data_type: str) -> Tuple[bool, str]:
    """
    Getting information for the next request based on the response json data

    :param response_obj: StorageLocation where JSON response is stored
    :param ret_data_type: String of what type of data from JSON is being pulled
    :returns: Tuple containing if there's a next page and endCursor
    """
    with response_json.open('r') as open_ref:
        tmp_obj = json.load(open_ref)
    _response_integrity_check(tmp_obj)
    page_info = tmp_obj['data'][ret_data_type]['pageInfo']
    return (page_info['hasNextPage'], page_info.get('endCursor'))

def get_ghsa_data(url: str, tmp_loc: StorageLocation, gh_token: str, date_str: str,
        pub_datetime: datetime=None, proxies: Dict=None) -> None:
    """
    Gets GHSA data from Github, does this through provided token and stores responses in
    JSON files at generated StorageLocations

    *WARNING: pub_datetime from what I could tell from resulting API calls didn't work
    in GitHub GQL API

    :param url: String URL of where call destination is for Github GQL API
    :param tmp_loc: StorageLocation of where JSON response files will be stored
    :param gh_token: String token used for Github GQL API requests
    :param date_str: Date as a string for file creation
    :param pub_datetime: Datetime object of last publish date to limit request needs
    :param proxies: Dictionary of proxy settings for requests
    :returns: None
    """
    file_prefix = f"ghsa_data_{date_str}_"
    query_vars = {'first': 100}
    if pub_datetime:
        query_vars['publishedSince'] = pub_datetime.strftime('%Y-%m-%dT%H:%M:%S+00:00')
    entry_index = 0
    tmp_file: StorageLocation = tmp_loc.join_loc(f'{file_prefix}{entry_index}.json')
    has_next = True
    headers = {"Authorization": f"Bearer {gh_token}", 'Content-Type': 'application/json'}
    if tmp_file.exists():
        final_info: Tuple[int, Tuple[str, bool]] = get_resume_info(tmp_loc,
            rf'{file_prefix}[0-9]+.json', file_prefix, _get_next_request_info,
            ret_data_type='securityAdvisories')
        entry_index = final_info[0] + 1
        has_next = final_info[1][0]
        query_vars['after'] = final_info[1][1]
    while has_next:
        tmp_file = tmp_loc.join_loc(f'{file_prefix}{entry_index}.json')
        ret_tuple: Tuple[bool, str] = request_stream_to_file(url, tmp_file, headers=headers,
            json_obj={'query': GHSA_GQL, "variables": query_vars}, request_type='POST',
            file_callback=_get_next_request_info, ret_data_type='securityAdvisories',
            proxies=proxies)
        has_next = ret_tuple[0]
        query_vars['after'] = ret_tuple[1]
        entry_index += 1

def get_ghsa_update_data(url: str, tmp_loc: StorageLocation, gh_token: str, date_str: str,
        update_datetime: datetime=None, proxies: Dict=None) -> None:
    """
    Gets GHSA data from Github base on the last datetime that entrie swere updated

    *WARNING: update_datetime from what I could tell from resulting API calls didn't work
    in GitHub GQL API

    :param url: String URL of where call destination is for Github GQL API
    :param tmp_loc: StorageLocation of where JSON response files will be stored
    :param gh_token: String token used for Github GQL API requests
    :param date_str: Date as a string for file creation
    :param update_datetime: Datetime object of last update date to limit request needs
    :param proxies: Dictionary of proxy settings for requests
    :returns: None
    """
    file_prefix = f"ghsa_update_data_{date_str}_"
    query_vars = {'first': 100}
    if update_datetime:
        query_vars['updatedSince'] = update_datetime.isoformat()
    entry_index = 0
    tmp_file: StorageLocation = tmp_loc.join_loc(f'{file_prefix}{entry_index}.json')
    has_next = True
    headers = {"Authorization": f"Bearer {gh_token}", 'Content-Type': 'application/json'}
    if tmp_file.exists():
        final_info: Tuple[int, Tuple[str, bool]] = get_resume_info(tmp_loc,
            rf'{file_prefix}[0-9]+.json', file_prefix, _get_next_request_info,
            ret_data_type='securityAdvisories')
        entry_index = final_info[0] + 1
        has_next = final_info[1][0]
        query_vars['after'] = final_info[1][1]
    while has_next:
        tmp_file = tmp_loc.join_loc(f'{file_prefix}{entry_index}.json')
        ret_tuple: Tuple[bool, str] = request_stream_to_file(url, tmp_file, headers=headers,
            json_obj={'query': GHSA_GQL, "variables": query_vars}, request_type='POST',
            file_callback=_get_next_request_info, ret_data_type='securityAdvisories',
            proxies=proxies)
        has_next = ret_tuple[0]
        query_vars['after'] = ret_tuple[1]
        entry_index += 1

def get_git_vuln_data(url: str, tmp_loc: StorageLocation, gh_token: str, date_str: str,
        proxies: Dict=None) -> None:
    """
    Gets GHSA vuln data for specifics on a given vuln

    :param url: String URL of where call destination is for Github GQL API
    :param tmp_loc: StorageLocation of where JSON response files will be stored
    :param gh_token: String token used for Github GQL API requests
    :param date_str: Date as a string for file creation
    :param proxies: Dictionary of proxy settings for requests
    :returns: None
    """
    file_prefix = f"git_vuln_data_{date_str}_"
    query_vars = {'first': 100}
    entry_index = 0
    tmp_file: StorageLocation = tmp_loc.join_loc(f'{file_prefix}{entry_index}.json')
    has_next = True
    headers = {"Authorization": f"Bearer {gh_token}", 'Content-Type': 'application/json'}
    if tmp_file.exists():
        final_info: Tuple[int, Tuple[bool, str]] = get_resume_info(tmp_loc,
            rf'{file_prefix}[0-9]+.json', file_prefix, _get_next_request_info,
            ret_data_type='securityVulnerabilities')
        entry_index = final_info[0]
        has_next = final_info[1][0]
        query_vars['after'] = final_info[1][1]
    while has_next:
        tmp_file = tmp_loc.join_loc(f'{file_prefix}{entry_index}.json')
        ret_tuple: Tuple[bool, str] = request_stream_to_file(url, tmp_file, headers=headers,
            json_obj={'query': GH_VULN_GQL, "variables": query_vars}, request_type='POST',
            file_callback=_get_next_request_info, ret_data_type='securityVulnerabilities',
            proxies=proxies)
        has_next = ret_tuple[0]
        query_vars['after'] = ret_tuple[1]
        entry_index += 1
