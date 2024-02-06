"""nist/tasks.py

Author: neo154
Version: 0.1.0
Date Modified: 2024-02-05

Contains the task object for CISA that are create for updating and maintaining the CISA KEV
catalogue and making it available in a DB
"""

import re
from datetime import datetime
from logging import INFO
from typing import Dict, List, Union

import pandas as pd
from afk import CredsManagerInterface, StorageConfig, StorageLocation
from afk.db.connection import (_SupportedDialectsType, confirm_table_exists,
                               create_tables, df_bulk_insert_to_db,
                               df_bulk_update_to_db, get_table_pk_df)
from afk.task import INTERACTIVE, _defaultLogger
from sqlalchemy import func, select

from secdata_collection.datafeeds.base_datafeed import BaseDBDatafeedTask
from secdata_collection.datafeeds.nist.api_conn import (
    get_nist_cves_update, get_nist_full_datafiles)
from secdata_collection.datafeeds.nist.db.models import (CVEEntry,
                                                         CVEEntryDB2DfMapping,
                                                         CVEEntryDf2DBMapping,
                                                         CVSSEntry,
                                                         CVSSEntryDB2DfMapping,
                                                         CVSSEntryDf2DBMapping)
from secdata_collection.datafeeds.nist.transformation import (
    nist_cve_2_csv, type_cve_info_df, type_cvss_info_df, check_empty_ret)


class NISTDBTask(BaseDBDatafeedTask):
    """Task used to download and update the CISA Kev in a DB"""

    def __init__(self, db_host: str, db_dialect: _SupportedDialectsType,
            db_creds_manager: CredsManagerInterface, db_name: str=None, db_driver: str=None,
            db_port: int=None, nist_creds_manager: CredsManagerInterface=None,
            task_name: str='nist_db_generic', primary_cvss_only: bool=True,
            run_type: str='testing', override: bool = False, storage_config: StorageConfig=None,
            interactive: bool=INTERACTIVE, **kwargs) -> None:
        super().__init__(db_host, db_dialect, db_creds_manager, db_name, db_driver, db_port,
            'nist', task_name, run_type, True, True, override, datetime.now(),
            storage_config, kwargs.get('logger', _defaultLogger), kwargs.get('logger_level', INFO),
            interactive)
        self.__request_proxies = kwargs.get('proxies')
        self.__base_url = "https://services.nvd.nist.gov/rest/json"
        self.__creds_manager = nist_creds_manager
        self.__auth_headers = None
        self.__primary_cvss_only = primary_cvss_only

    @property
    def creds_manager(self) -> CredsManagerInterface:
        """Gets creds manager for NIST tasks"""
        return self.__creds_manager

    @property
    def request_proxies(self) -> Union[Dict, None]:
        """Returns request proxies if any exist"""
        return self.__request_proxies

    @property
    def base_url(self) -> str:
        """Gets NIST base url"""
        return self.__base_url

    @property
    def primary_cvss_only(self) -> bool:
        """Returns if task is configured for only primarycvss records only"""
        return self.__primary_cvss_only

    def get_headers(self) -> Dict:
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

class NISTCVEDBUpdate(NISTDBTask):
    """Used to upcate NIST CVE information"""

    def __init__(self, db_host: str, db_dialect: _SupportedDialectsType,
            db_creds_manager: CredsManagerInterface, db_name: str = None, db_driver: str = None,
            db_port: int = None, nist_creds_manager: CredsManagerInterface = None,
            primary_cvss_only: bool = True, run_type: str = 'testing', override: bool = False,
            storage_config: StorageConfig = None, interactive: bool = INTERACTIVE,
            **kwargs) -> None:
        super().__init__(db_host, db_dialect, db_creds_manager, db_name, db_driver, db_port,
            nist_creds_manager, 'nist_cve_db_update', primary_cvss_only, run_type, override,
            storage_config, interactive,
            **kwargs)
        self.storage.archive_file = 'nist_cve_db_update.tar.bz2'

    def main(self) -> None:
        """Main execution to download and manage the update files"""
        self.check_run_conditions()
        gen_tables = False
        update = True
        __db_engine = self.db_engine
        __logger = self.logger
        today_str = self.storage.report_date_str
        with __db_engine.connect() as db_conn:
            if not (confirm_table_exists(db_conn, CVEEntry) \
                    and confirm_table_exists(db_conn, CVSSEntry)):
                gen_tables = True
        if gen_tables:
            update = False
            __logger.info("NIST Table(s) missing, attempting to create them")
            create_tables([CVEEntry, CVSSEntry], __db_engine, __logger)
        proxies = self.request_proxies
        headers = self.get_headers()
        if update:
            cve_pk_df = get_table_pk_df(__db_engine, CVEEntry, CVEEntryDB2DfMapping)
            cvss_pk_df = get_table_pk_df(__db_engine, CVSSEntry, CVSSEntryDB2DfMapping)
            if cve_pk_df.index.size<=0:
                update = False
            else:
                with __db_engine.connect() as tmp_conn:
                    result_cursor = tmp_conn.execute(select(func.max(CVEEntry.LST_MOD_DATETIME)))
                    last_mod_datetime = result_cursor.first()[0]
        if update:
            __logger.info("Getting updated data for NIST NVD for CVEs")
            file_prefix = f'nist_cve_inc_{today_str}'
            get_nist_cves_update(f'{self.base_url}/cves/2.0', self.storage.tmp_loc,
                headers, last_mod_datetime, logger_ref=__logger, proxies=proxies)
        else:
            __logger.info("Getting full data for NIST NVD for CVEs")
            file_prefix = f'nist_cve_init_db_{today_str}'
            get_nist_full_datafiles(f'{self.base_url}/cves/2.0', self.storage.tmp_loc,
                headers, logger_ref=__logger, proxies=proxies)
        file_pattern = rf'{file_prefix}_[0-9]+\.json'
        nist_full_data_files: List[StorageLocation] = []
        parsed_cve_files: List[StorageLocation] = []
        parsed_cvss_files: List[StorageLocation] = []
        possible_file: StorageLocation
        first_file = True
        for possible_file in self.storage.tmp_loc.iter_location():
            if re.match(file_pattern, possible_file.name):
                self.storage.add_to_archive_list(possible_file)
                nist_full_data_files.append(possible_file)
                tmp_cve_file, tmp_cvss_file = nist_cve_2_csv(possible_file,
                    self.primary_cvss_only, False)
                if update and first_file:
                    # Check to see if there is no data being returned from this call
                    if check_empty_ret(possible_file):
                        self.storage.create_archive(cleanup=True)
                        tmp_cve_file.delete(logger=__logger)
                        tmp_cvss_file.delete(logger=__logger)
                        return
                    first_file = False
                parsed_cve_files.append(tmp_cve_file)
                self.storage.add_to_archive_list(tmp_cve_file)
                parsed_cvss_files.append(tmp_cvss_file)
                self.storage.add_to_archive_list(tmp_cvss_file)
        cve_df_l = []
        for cve_csv_file in parsed_cve_files:
            with cve_csv_file.open('r', encoding='utf-8') as open_csv:
                cve_df_l.append(pd.read_csv(open_csv))
        cvss_df_l = []
        for cvss_cvs_file in parsed_cvss_files:
            with cvss_cvs_file.open('r', encoding='utf-8') as open_csv:
                cvss_df_l.append(pd.read_csv(open_csv))
        cve_df = type_cve_info_df(pd.concat(cve_df_l, ignore_index=True))
        cvss_df = type_cvss_info_df(pd.concat(cvss_df_l, ignore_index=True))
        if update:
            cve_pk_df['is_in_db'] = True
            cvss_pk_df['is_in_db'] = True
            cvss_pk_df['type'] = cvss_pk_df['type'].apply(lambda x: x.name)
            new_cve_record_v = cve_df.merge(cve_pk_df, how='left')['is_in_db'].isna()
            new_cve_records_df = cve_df[new_cve_record_v]
            update_cve_records_df = cve_df[~new_cve_record_v]
            df_bulk_insert_to_db(new_cve_records_df, CVEEntry, CVEEntryDf2DBMapping, __db_engine,
                self.storage.tmp_loc, __logger)
            df_bulk_update_to_db(update_cve_records_df, CVEEntry, CVEEntryDf2DBMapping,
                __db_engine, self.storage.tmp_loc, __logger)
            new_cvss_record_v = cvss_df.merge(cvss_pk_df, how='left')['is_in_db'].isna()
            new_cvss_records_df = cvss_df[new_cvss_record_v]
            update_cvss_records_df = cvss_df[~new_cvss_record_v]
            df_bulk_insert_to_db(new_cvss_records_df, CVSSEntry, CVSSEntryDf2DBMapping,
                __db_engine, self.storage.tmp_loc, __logger, export_datafile_on_fail=True)
            df_bulk_update_to_db(update_cvss_records_df, CVSSEntry, CVSSEntryDf2DBMapping,
                __db_engine, self.storage.tmp_loc, __logger, export_datafile_on_fail=True)
        else:
            df_bulk_insert_to_db(cve_df, CVEEntry, CVEEntryDf2DBMapping, __db_engine,
                self.storage.tmp_loc, __logger, export_datafile_on_fail=True)
            df_bulk_insert_to_db(cvss_df, CVSSEntry, CVSSEntryDf2DBMapping, __db_engine,
                self.storage.tmp_loc, __logger, export_datafile_on_fail=True)
        self.storage.create_archive(self.storage.archive_files, self.storage.archive_file, True)
