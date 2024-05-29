"""github/transformation.py

Author: neo154
Version: 0.1.0
Date Modified: 2024-05-26

Transformation for those files that are downloaded from Github's API, primarily GQL API
and transforms them into records desired
"""

from typing import Dict, List, Tuple, Union
import json

import pandas as pd
import numpy as np

from afk import StorageLocation, export_df

def parse_ghsa_data(ghsa_nodes: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """
    Parsing GHSA JSON data info into specific lists of records for the ghsas and their related
    vuln identifiers to be marshaled into DataFrames

    :param ghsa_nodes: List of dictionary records with raw GHSA data
    :returns: Tuple of Lists of records for GHSA data and related vuln records
    """
    sec_advs_l = []
    ghsa_cve_map_l = []
    for ghsa_node in ghsa_nodes:
        cvss_rec = ghsa_node.get('cvss')
        ghsa_id = ghsa_node.get("ghsaId")
        sec_advs_rec = {
            "ghsa_id": ghsa_id,
            "origin": ghsa_node.get("origin"),
            "published_at": ghsa_node.get("publishedAt"),
            "description": ghsa_node.get("description"),
            "severity": ghsa_node.get("severity"),
            "summary": ghsa_node.get("summary"),
            "updated_at": ghsa_node.get("updatedAt"),
            "classification": ghsa_node.get("classification"),
            "cvss_score": None,
            "cvss_vector_string": None
        }
        if cvss_rec:
            sec_advs_rec['cvss_score'] = cvss_rec.get('score')
            sec_advs_rec['cvss_vector_string'] = cvss_rec.get('vectorString')
        sec_advs_l.append(sec_advs_rec)
        for identifier in ghsa_node.get('identifiers', []):
            if identifier.get('type')!='GHSA':
                ghsa_cve_map_l.append({
                    'ghsa_id': ghsa_id,
                    'identifier_type': identifier.get('type'),
                    'identifier': identifier.get('value')
                })
    return (sec_advs_l, ghsa_cve_map_l)

def parse_ghsa_vuln_data(ghsa_vuln_nodes: List[Dict]) -> List[Dict]:
    """
    Parses ghsa vuln data into a list of usable records

    :param ghsa_vuln_nodes: List of Dictionary raw JSON records
    :returns: List of Records that can be easily converted to a DataFrame
    """
    ghsa_vuln_data = []
    for ghsa_node in ghsa_vuln_nodes:
        package_ref: Dict[str, str] = ghsa_node.get('package')
        first_patched: Dict[str, str] = ghsa_node.get('firstPatchedVersion')
        patched_version = None
        if first_patched:
            patched_version = first_patched.get('identifier')
        ghsa_vuln_data.append({
            'ghsa_id': ghsa_node.get('advisory').get("ghsaId"),
            'first_patched_version': patched_version,
            'severity': ghsa_node.get('severity'),
            'package_name': package_ref.get('name'),
            'package_ecosystem': package_ref.get('ecosystem'),
            'vuln_version_range': ghsa_node.get('vulnerableVersionRange'),
            'updated_at': ghsa_node.get('updatedAt')
        })
    return ghsa_vuln_data

def type_ghsa_info(ghsa_records: Union[pd.DataFrame, List]) -> pd.DataFrame:
    """
    Types GHSA info from a list of records or a dataframe into db insertion or data analysis
    ready form

    :param ghsa_records: List of Dictionary records or a Dataframe containing GHSA records
    :returns: DataFrame with fully typed data
    """
    if isinstance(ghsa_records, list):
        ghsa_df = pd.DataFrame(ghsa_records)
    else:
        ghsa_df = ghsa_records
    ghsa_df['published_at'] = pd.to_datetime(ghsa_df['published_at'],
        format='ISO8601', utc=True)
    ghsa_df['updated_at'] = pd.to_datetime(ghsa_df['updated_at'],
        format='ISO8601', utc=True)
    ghsa_df.loc[ ((ghsa_df['cvss_score']==0) & ghsa_df['cvss_vector_string'].isna()),
        'cvss_score'] = np.nan
    return ghsa_df

def type_ghsa_cve_info(ghsa_cve_records: Union[pd.DataFrame, List]) -> pd.DataFrame:
    """
    Types GHSA info from a DataFrame or list of GHSA vuln mapper records to a dataframe

    :param ghsa_cve_records: Dataframe or list of records for GHSA vuln mappers
    :returns: DataFrame of GHSA vuln mapped data
    """
    if isinstance(ghsa_cve_records, list):
        return pd.DataFrame(ghsa_cve_records)
    return ghsa_cve_records

def ghsa_2_csv(json_loc: StorageLocation, ret_data: bool=False) \
        -> Union[Tuple[List[Dict], List[Dict]], Tuple[StorageLocation, StorageLocation]]:
    """
    Converts the ghsa files to csv files for both the GHSA data and vuln mapper data

    :param json_loc: StorageLocation object for where json file is located
    :param ret_data: Boolean of whether to return data or not
    :returns: List of records parsed from JSON file or files that contains paresed records
    """
    with json_loc.open('rb') as file_ref:
        json_obj: Dict = json.load(file_ref)
    f_basename = json_loc.name.split('.')[0]
    ghsa_records = parse_ghsa_data(json_obj.get('data').get('securityAdvisories')\
        .get('nodes'))
    if ret_data:
        return ghsa_records
    export_ghsa_file = json_loc.parent.join_loc(f'{f_basename}.csv')
    export_cve_file = json_loc.parent.join_loc(f'{f_basename}_vuln_ids.csv')
    export_df(pd.DataFrame(ghsa_records[0]), export_ghsa_file)
    export_df(pd.DataFrame(ghsa_records[1]), export_cve_file)
    return (export_ghsa_file, export_cve_file)

def type_ghsa_from_db(db_df: pd.DataFrame) -> pd.DataFrame:
    """
    Typing GHSA from the DB for analysis or update based operations

    :param db_df: Dataframe directly from Databse for GHSA data
    :returns: Analysis ready dataframe containing GHSA data
    """
    db_df['severity'] = db_df['severity'].apply(lambda x: x.name)
    db_df['published_at'] = pd.to_datetime(db_df['published_at'], utc=True)
    db_df['updated_at'] = pd.to_datetime(db_df['updated_at'], utc=True)
    db_df.loc[ ((db_df['cvss_score']==0) & (db_df['cvss_vector_string'].isna())),
        'cvss_score'] = np.nan
    return db_df

def ghsa_vuln_2_csv(json_loc: StorageLocation, ret_data: bool=False) \
        -> Union[List[Dict], StorageLocation]:
    """
    Converts GHSA Vvuln information data into parsed files or List of records

    :param json_loc: StorageLocation for JSON data is stored
    :param ret_data: Boolean indicating whether to return data
    :returns: StorageLocation of parsed data or Raw data
    """
    with json_loc.open('rb') as file_ref:
        json_obj: Dict = json.load(file_ref)
    f_basename = json_loc.name.split('.')[0]
    ghsa_vuln_records = parse_ghsa_vuln_data(json_obj.get('data').get('securityVulnerabilities')\
        .get('nodes'))
    if ret_data:
        return ghsa_vuln_records
    export_ghsa_vuln_file = json_loc.parent.join_loc(f'{f_basename}.csv')
    export_df(pd.DataFrame(ghsa_vuln_records), export_ghsa_vuln_file)
    return export_ghsa_vuln_file

def type_vuln_data(ghsa_vuln_records: Union[pd.DataFrame, List[Dict]]) -> pd.DataFrame:
    """
    Types GHSA vuln data into a fully typed and usable DataFrame

    :param ghsa_vuln_records: DataFrame or List of records for GHSA vuln details
    :returns: DataFrame containing GHSA vulnerability detail records
    """
    if isinstance(ghsa_vuln_records, list):
        return pd.DataFrame(ghsa_vuln_records)
    ghsa_vuln_records['updated_at'] = pd.to_datetime(ghsa_vuln_records['updated_at'], utc=True)
    return ghsa_vuln_records
