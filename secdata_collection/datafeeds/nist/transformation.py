"""nist/transformation.py

Author: neo154
Version: 0.1.0
Date Modified: 2024-02-05

Responsible for transforming raw JSON data from the NIST API responses to usable CSV(s) file(s)
for loading and data analysis
"""

import json
import re
from typing import Dict, List, Tuple, Union

import pandas as pd
from afk import StorageLocation, export_df


def _parse_cvss_info_rec(cve_id: str, cve_metric_ref: Union[List[Dict], None],
        primary_only: bool=True) -> List[Dict]:
    """
    Parse single cvss entry, going for primary only unless configured otherwise

    :param cve_id: String of CVE identifier
    :param cve_metric_ref: List of dictionary entries or None for CVE metrics
    :param primary_only: Boolean indicating whether to get primary records only or more
    :returns: List of dictinaries containing CVSS data related to a given CVE
    """
    ret_l = []
    if cve_metric_ref is None:
        return ret_l
    for cve_metric_rec in cve_metric_ref:
        metric_record_type = cve_metric_rec.get('type')
        if metric_record_type=='Primary' or not primary_only:
            cvss_data_ref: Dict = cve_metric_rec['cvssData']
            tmp_rec = {
                'cve_id': cve_id,
                'version': cvss_data_ref['version'],
                'source': cve_metric_rec.get('source'),
                'type': metric_record_type,
                'vector_string': cvss_data_ref.get('vectorString'),
                'attack_vector': cvss_data_ref.get('accessVector'),
                'attack_complexity': cvss_data_ref.get('accessComplexity'),
                'confidentiality_impact': cvss_data_ref.get('confidentialityImpact'),
                'integrity_impact': cvss_data_ref.get('integrityImpact'),
                'availability_impact': cvss_data_ref.get('availabilityImpact'),
                'base_score': cvss_data_ref.get('baseScore'),
                'base_severity': cve_metric_rec.get('baseSeverity'),
                'exploitability_score': cve_metric_rec.get('exploitabilityScore'),
                'impact_score': cve_metric_rec.get('impactScore')
            }
            if tmp_rec['version']==2.0:
                tmp_rec['base_severity'] = cve_metric_rec.get('baseSeverity')
            else:
                tmp_rec['base_severity'] = cvss_data_ref.get('baseSeverity')
            ret_l.append(tmp_rec)
    return ret_l

def nist_cve_2_csv(json_loc: StorageLocation, primary_cvss_only: bool=True,
            ret_data: bool=False
        ) -> Union[Tuple[List[Dict], List[Dict]], Tuple[StorageLocation, StorageLocation]]:
    """
    Transforms raw CVE files from the NIST api to csv

    :param json_loc: StorageLocation of where the json data is stored
    :param primary_cvss_only: Boolean indicating whether to get primary records only or more
    :param ret_data: Boolean indicating to return the loaded data or not
    :returns: Tuple of Dictionary entires for the CVE and CVSS records, or storage locations where
                the fully parsed data is stored
    """
    with json_loc.open('rb') as file_ref:
        json_obj = json.load(file_ref)
    f_basename = json_loc.name.split('.')[0]
    cve_info = []
    cvss_records = []
    for item in json_obj['vulnerabilities']:
        tmp_ref: Dict = item['cve']
        cve_id = tmp_ref.get('id')
        if cve_id=='CVE-2023-26158':
            tmp_info = next((desc_entry.get('value') \
                for desc_entry in  tmp_ref.get('descriptions', []) \
                    if desc_entry.get('lang')=='en'), None)
            tmp_info = tmp_info.strip()
            tmp_info = re.sub(r'([\n\r]+)', ' ', tmp_info)
        metrics_ref: Dict = tmp_ref.get('metrics')
        cve_info.append({
            'cve_id': cve_id,
            'source_id': tmp_ref.get('sourceIdentifier'),
            'published_datetime': tmp_ref.get('published'),
            'last_modified_datetime': tmp_ref.get('lastModified'),
            'status': tmp_ref.get('vulnStatus'),
            'description': next((re.sub(r'([\n\r]+)', ' ', desc_entry.get('value').strip()) \
                for desc_entry in  tmp_ref.get('descriptions', []) \
                    if desc_entry.get('lang')=='en'), None)
        })
        cvss_records += _parse_cvss_info_rec(cve_id, metrics_ref.get('cvssMetricV2'),
            primary_cvss_only)
        cvss_records += _parse_cvss_info_rec(cve_id, metrics_ref.get('cvssMetricV30'),
            primary_cvss_only)
        cvss_records += _parse_cvss_info_rec(cve_id, metrics_ref.get('cvssMetricV31'),
            primary_cvss_only)
    if ret_data:
        return (cve_info, cvss_records)
    export_cve_file = json_loc.parent.join_loc(f'{f_basename}_cve_info.csv')
    export_cvss_file = json_loc.parent.join_loc(f'{f_basename}_cvss_info.csv')
    cve_info_df = pd.DataFrame(cve_info)
    cvss_info_df = pd.DataFrame(cvss_records)
    export_df(cve_info_df, export_cve_file)
    export_df(cvss_info_df, export_cvss_file)
    return (export_cve_file, export_cvss_file)

def type_cve_info_df(cve_info_recs: Union[pd.DataFrame, List[Dict]]) -> pd.DataFrame:
    """
    Types records from cve info records

    :param cve_info_recs: CVE records in DataFrame or List of Dictionary entries
    :returns: DataFrame of fully typed NIST CVE data
    """
    if isinstance(cve_info_recs, list):
        cve_info_recs = pd.DataFrame(cve_info_recs)
    cve_info_recs['published_datetime'] = pd.to_datetime(
        cve_info_recs['published_datetime'], format='ISO8601', utc=True)
    cve_info_recs['last_modified_datetime'] = pd.to_datetime(
        cve_info_recs['last_modified_datetime'], format='ISO8601', utc=True)
    return cve_info_recs

def type_cvss_info_df(cvss_info_recs: Union[pd.DataFrame, List[Dict]]) -> pd.DataFrame:
    """
    Types records from cvss records

    :param cve_info_recs: CVSS records in DataFrame or List of Dictionary entries
    :returns: DataFrame of fully typed NIST CVSS data
    """
    if isinstance(cvss_info_recs, list):
        cvss_info_recs = pd.DataFrame(cvss_info_recs)
    cvss_info_recs['version'] = cvss_info_recs['version'].astype('str')
    return cvss_info_recs

def check_empty_ret(ret_storage: StorageLocation) -> bool:
    """Checks if return file was empty or not"""
    with ret_storage.open('r') as open_storage:
        tmp_obj = json.load(open_storage)
    return tmp_obj['resultsPerPage']==0
