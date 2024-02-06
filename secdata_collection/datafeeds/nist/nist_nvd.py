"""nist_nvd.py

Author: neo154
Version: 0.1.0
Date Modified: 2024-02-05

Object and means of collecting and basic management of NIST related data
"""

import re
from datetime import date
from logging import Logger
from typing import Dict, List

import pandas as pd
from afk import ArchiveFile, Storage, StorageLocation, export_df
from afk.afk_logging import generate_logger
from afk.utils.creds.creds_interface import CredsManagerInterface

from secdata_collection.datafeeds.base_datafeed import Datafeed, check_rotate
from secdata_collection.datafeeds.nist.api_conn import (
    get_cve, get_cves, get_nist_full_datafiles)
from secdata_collection.datafeeds.nist.transformation import (nist_cve_2_csv,
                                                              type_cve_info_df)
from secdata_collection.utils.transform import consolidate_partial_datafiles

_DEFAULT_LOGGER = generate_logger(__name__)

class NistNvdDatafeed(Datafeed):
    """CISA KEV Datafeed object that will have the datafiles it collects, manages, and archives"""

    def __init__(self, storage_ref: Storage, base_nist_url: str=None,
            creds_manager: CredsManagerInterface=None, logger_ref: Logger=_DEFAULT_LOGGER) -> None:
        super().__init__(storage_ref, creds_manager, logger_ref)
        if base_nist_url is None:
            base_nist_url = "https://services.nvd.nist.gov/rest/json"
        self.__base_url = base_nist_url
        self.__cve_pull_data_archive = self.storage.gen_archivefile_ref('nist_cve_full.tar.gz')
        self.__cve_full_datafile = self.storage.gen_datafile_ref('nist_cve_full.csv.gz')
        self.__cvss_full_datafile = self.storage.gen_datafile_ref('nist_cvss_full.csv.gz')
        self.__auth_headers = None

    def __get_headers(self) -> Dict:
        """
        Builds and gets headers and checks for credentials manager if isn't already present

        :returns: Dictionary of api key headers if available
        """
        if self.__auth_headers is None:
            headers = {}
            if self.creds_manager is not None:
                tmp_key = self.creds_manager.get_apikey()
                if tmp_key is not None:
                    headers['apiKey'] = tmp_key
            self.__auth_headers = headers
        return self.__auth_headers

    def get_full_nist_datafiles(self, proxies: Dict=None, override: bool=False,
            low_memory: bool=True, primary_cvss_only: bool=True) -> None:
        """
        Gets the full nist data and store them as datafiles, if low memory is set it will parse
        files and load them incrementally rather than keeping each chunk in memory for writing

        :param proxes: Dictionary of proxy setting for requests
        :param override: Boolean indicating if datafiles and archive files should be rotated
        :param low_memory: Boolean indicating if this should try to keep memory usage low
        :param primary_cvss_only: Boolean indicating whether to get primary records only or more
        :returns None:
        """
        __logger = self.logger
        check_rotate(self.__cve_full_datafile, override, __logger)
        check_rotate(self.__cvss_full_datafile, override, __logger)
        check_rotate(self.__cve_pull_data_archive, override, __logger)
        __logger.info("Getting full data for NIST NVD for CVEs")
        headers = self.__get_headers()
        today_str = date.today().strftime("%Y_%m_%d")
        get_nist_full_datafiles(f'{self.__base_url}/cves/2.0', self.storage.tmp_loc,
            headers, logger_ref=__logger, proxies=proxies)
        nist_full_data_files: List[StorageLocation] = []
        if low_memory:
            parsed_cve_files: List[StorageLocation] = []
            parsed_cvss_files: List[StorageLocation] = []
            possible_file: StorageLocation
            for possible_file in self.storage.tmp_loc.iter_location():
                if re.match(rf'nist_cves_full_{today_str}_[0-9]+\.json', possible_file.name):
                    nist_full_data_files.append(possible_file)
                    tmp_cve_file, tmp_cvss_file = nist_cve_2_csv(possible_file, primary_cvss_only,
                        False)
                    parsed_cve_files.append(tmp_cve_file)
                    parsed_cvss_files.append(tmp_cvss_file)
            consolidate_partial_datafiles(self.__cve_full_datafile, parsed_cve_files)
            for del_final in parsed_cve_files:
                del_final.delete(__logger)
            consolidate_partial_datafiles(self.__cvss_full_datafile, parsed_cvss_files)
            for del_final in parsed_cvss_files:
                del_final.delete(__logger)
        else:
            cve_recs: List[Dict] = []
            cvss_recs: List[Dict] = []
            for possible_file in self.storage.tmp_loc.iter_location():
                if re.match(rf'nist_cves_full_{today_str}_[0-9]+\.json', possible_file.name):
                    nist_full_data_files.append(possible_file)
                    tmp_ret = nist_cve_2_csv(possible_file, primary_cvss_only, True)
                    cve_recs += tmp_ret[0]
                    cvss_recs += tmp_ret[1]
            export_df(type_cve_info_df(cve_recs), self.__cve_full_datafile)
            export_df(pd.DataFrame(cvss_recs), self.__cvss_full_datafile)
        with ArchiveFile(self.__cve_pull_data_archive, logger_ref=__logger).open('w') \
                as archive_ref:
            for arc_file in nist_full_data_files:
                archive_ref.addfile(arc_file, None, None, False)
                arc_file.delete(logger=__logger)
            archive_ref.addfile(self.__cve_full_datafile, None, None, False)
            archive_ref.addfile(self.__cvss_full_datafile, None, None, False)

    def get_cve(self, cve_id: str) -> Dict:
        """
        Gets single cve from the NIST API

        :param cve_id: String identifying the CVE ID to look for via the NIST API
        :returns: Dictionary data on the CVE
        """
        return get_cve(f"{self.__base_url}/cves/2.0", cve_id, self.__get_headers())

    def get_cves(self, cve_ids: List[str]) -> List[Dict]:
        """
        Gets multiple cve records from the NIST API

        :param cve_id: List of Strings of the CVE IDs to look for via the NIST API
        :returns: List of dictionary CVe records
        """
        return get_cves(f"{self.__base_url}/cves/2.0", cve_ids, self.__get_headers())
