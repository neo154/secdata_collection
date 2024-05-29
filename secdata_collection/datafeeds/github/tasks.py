"""github/tasks.py

Author: neo154
Version: 0.1.0
Date Modified: 2024-05-29

Contains the task object for CISA that are create for updating and maintaining the CISA KEV
catalogue and making it available in a DB
"""

import re
from datetime import datetime
from logging import INFO
from typing import Tuple

import pandas as pd
from afk import CredsManagerInterface, Storage, StorageConfig, StorageLocation
from afk.db.connection import (_SupportedDialectsType, confirm_table_exists,
                               create_tables, df_bulk_insert_to_db,
                               df_bulk_update_to_db, get_table_df,
                               get_table_pk_df)
from afk.task import INTERACTIVE, _defaultLogger

from secdata_collection.datafeeds.base_datafeed import BaseDBDatafeedTask
from secdata_collection.datafeeds.github.api_conn import (get_ghsa_data,
                                                          get_git_vuln_data)
from secdata_collection.datafeeds.github.db.models import (
    GHSAEntry, GHSAEntryDB2DfMapping, GHSAEntryDf2DBMapping, GHSAVulnEntry,
    GHSAVulnEntryDB2DfMapping, GHSAVulnEntryDetails,
    GHSAVulnEntryDetailsDB2DfMapping, GHSAVulnEntryDetailsDf2DBMapping,
    GHSAVulnEntryDf2DBMapping)
from secdata_collection.datafeeds.github.transformation import (
    ghsa_2_csv, ghsa_vuln_2_csv, type_ghsa_cve_info, type_ghsa_from_db,
    type_ghsa_info, type_vuln_data)
from secdata_collection.utils.transform import get_updates_from_df


def _ret_files(storage_ref: Storage, f_pattern: str) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Does the full parsing for raw GHSA files and does the loading and transforming of the data
    to a useful DataFrame format

    :param storage_ref: Storage reference archives and tmp references
    :param f_pattern: String of file name pattern to search and parse GHSA data for
    :returns: Tuple operation ready GHSA DataFrame and GHSA to Vuln DataFrame
    """
    parsed_ghsa_files = []
    parsed_ghsa_cve_files = []
    possible_file: StorageLocation
    for possible_file in storage_ref.tmp_loc.iter_location():
        if re.match(f_pattern, possible_file.name):
            storage_ref.add_to_archive_list(possible_file)
            ghsa_file_tuple = ghsa_2_csv(possible_file, False)
            parsed_ghsa_files.append(ghsa_file_tuple[0])
            parsed_ghsa_cve_files.append(ghsa_file_tuple[1])
    ghsa_l = []
    for ghsa_file_ref in parsed_ghsa_files:
        with ghsa_file_ref.open('r', encoding='utf-8') as open_csv:
            ghsa_l.append(pd.read_csv(open_csv))
        storage_ref.add_to_archive_list(ghsa_file_ref)
    ghsa_cve_l = []
    for ghsa_cve_file_ref in parsed_ghsa_cve_files:
        with ghsa_cve_file_ref.open('r', encoding='utf-8') as open_csv:
            ghsa_cve_l.append(pd.read_csv(open_csv))
        storage_ref.add_to_archive_list(ghsa_cve_file_ref)
    return pd.concat(ghsa_l, ignore_index=True), pd.concat(ghsa_cve_l, ignore_index=True)

class GitHubDBUpdateTask(BaseDBDatafeedTask):
    """Task used to download and update the CISA Kev in a DB"""

    def __init__(self, db_host: str, db_dialect: _SupportedDialectsType,
            db_creds_manager: CredsManagerInterface, db_name: str=None, db_driver: str=None,
            db_port: int=None, github_creds_manager: CredsManagerInterface=None,
            task_name: str='github_ghsa_db_update',
            run_type: str='testing', override: bool = False, storage_config: StorageConfig=None,
            interactive: bool=INTERACTIVE, **kwargs) -> None:
        super().__init__(db_host, db_dialect, db_creds_manager, db_name, db_driver, db_port,
            'github', task_name, run_type, True, True, override, datetime.now(),
            storage_config, kwargs.get('logger', _defaultLogger), kwargs.get('logger_level', INFO),
            interactive)
        self.__request_proxies = kwargs.get('proxies')
        self.__base_url = "https://api.github.com/graphql"
        self.__creds_manager = github_creds_manager
        self.storage.archive_file = 'ghsa_db_update.tar.bz2'

    def main(self):
        """Main function for the task"""
        self.check_run_conditions()
        __db_engine = self.db_engine
        __logger = self.logger
        ghsa_creds_mgr = self.__creds_manager
        gen_tables = False
        __logger = _defaultLogger
        today_str = self.storage.report_date_str
        with __db_engine.connect() as db_conn:
            if not (confirm_table_exists(db_conn, GHSAEntry) \
                    and confirm_table_exists(db_conn, GHSAEntry)):
                gen_tables = True
            if not (confirm_table_exists(db_conn, GHSAVulnEntry) \
                    and confirm_table_exists(db_conn, GHSAVulnEntry)):
                gen_tables = True
        if gen_tables:
            __logger.info("GHSA Table(s) missing, attempting to create them")
            create_tables([GHSAEntry, GHSAVulnEntry], __db_engine, __logger)
        # Get the lastest update and create times
        get_ghsa_data(self.__base_url, self.storage.tmp_loc, ghsa_creds_mgr.get_apikey(),
            today_str, proxies=self.__request_proxies)
        new_ghsa_df, new_ghsa_cve_df = _ret_files(self.storage,
            f"ghsa_data_{today_str}_[0-9]+.json")
        new_ghsa_df = type_ghsa_info(new_ghsa_df)
        new_ghsa_cve_df = type_ghsa_cve_info(new_ghsa_cve_df)
        db_ghsa_df = type_ghsa_from_db(get_table_df(__db_engine, GHSAEntry, GHSAEntryDB2DfMapping))
        new_df, update_df = get_updates_from_df(db_ghsa_df, new_ghsa_df, ['ghsa_id'])
        df_bulk_insert_to_db(new_df, GHSAEntry, GHSAEntryDf2DBMapping, __db_engine,
            self.storage.tmp_loc, __logger)
        df_bulk_update_to_db(update_df, GHSAEntry, GHSAEntryDf2DBMapping, __db_engine,
            self.storage.tmp_loc, __logger)
        db_ghsa_vuln_df = get_table_df(__db_engine, GHSAVulnEntry, GHSAVulnEntryDB2DfMapping)
        new_df, update_df = get_updates_from_df(db_ghsa_vuln_df, new_ghsa_cve_df,
            ['identifier', 'ghsa_id'])
        df_bulk_insert_to_db(new_df, GHSAVulnEntry, GHSAVulnEntryDf2DBMapping, __db_engine,
            self.storage.tmp_loc, __logger)
        df_bulk_update_to_db(update_df, GHSAVulnEntry, GHSAVulnEntryDf2DBMapping, __db_engine,
            self.storage.tmp_loc, __logger)
        self.storage.create_archive(self.storage.archive_files, self.storage.archive_file, True)


class GitHubDBVulnDetailUpdateTask(BaseDBDatafeedTask):
    """Task used to download and update the CISA Kev in a DB"""

    def __init__(self, db_host: str, db_dialect: _SupportedDialectsType,
            db_creds_manager: CredsManagerInterface, ghsa_job_archive_loc: StorageLocation,
            db_name: str=None, db_driver: str=None,
            db_port: int=None, github_creds_manager: CredsManagerInterface=None,
            task_name: str='github_ghsa_vuln_dtl_db_update',
            run_type: str='testing', override: bool = False, storage_config: StorageConfig=None,
            interactive: bool=INTERACTIVE, **kwargs) -> None:
        super().__init__(db_host, db_dialect, db_creds_manager, db_name, db_driver, db_port,
            'github', task_name, run_type, True, True, override, datetime.now(),
            storage_config, kwargs.get('logger', _defaultLogger), kwargs.get('logger_level', INFO),
            interactive)
        self.__request_proxies = kwargs.get('proxies')
        self.__base_url = "https://api.github.com/graphql"
        self.__creds_manager = github_creds_manager
        self.storage.archive_file = 'ghsa_db_vuln_dtls_update.tar.bz2'
        self.storage.add_to_required_list(ghsa_job_archive_loc)

    def main(self):
        """Main function for the task"""
        self.check_run_conditions()
        __db_engine = self.db_engine
        __logger = self.logger
        ghsa_creds_mgr = self.__creds_manager
        __logger = _defaultLogger
        today_str = self.storage.report_date_str
        with __db_engine.connect() as db_conn:
            if not confirm_table_exists(db_conn, GHSAVulnEntryDetails):
                __logger.info("GHSA Table(s) missing, attempting to create them")
                create_tables([GHSAVulnEntryDetails], __db_engine, __logger)
        get_git_vuln_data(self.__base_url, self.storage.tmp_loc, ghsa_creds_mgr.get_apikey(),
            today_str, proxies=self.__request_proxies)
        f_pattern = f'git_vuln_data_{today_str}_'
        parsed_files = []
        for possible_file in self.storage.tmp_loc.iter_location():
            if re.match(f_pattern, possible_file.name):
                parsed_file = ghsa_vuln_2_csv(possible_file, False)
                self.storage.add_to_archive_list(possible_file)
                self.storage.add_to_archive_list(parsed_file)
                parsed_files.append(parsed_file)
        ret_l = []
        for parsed_file in parsed_files:
            with parsed_file.open('r', encoding='utf-8') as open_csv:
                ret_l.append(pd.read_csv(open_csv))
        ghsa_vuln_df = type_vuln_data(pd.concat(ret_l, ignore_index=True))
        db_ghsa_vuln_df = get_table_df(__db_engine, GHSAVulnEntryDetails,
            GHSAVulnEntryDetailsDB2DfMapping)
        new_df, update_df = get_updates_from_df(db_ghsa_vuln_df, ghsa_vuln_df, [
            'ghsa_id', 'package_name', 'package_ecosystem', 'vuln_version_range',
            'first_patched_version'])
        ghsa_pk = get_table_pk_df(__db_engine, GHSAEntry, GHSAEntryDB2DfMapping)
        new_df = new_df[ new_df['ghsa_id'].isin(ghsa_pk['ghsa_id']) ].reset_index()\
            .drop(columns='index')
        df_bulk_insert_to_db(new_df, GHSAVulnEntryDetails, GHSAVulnEntryDetailsDf2DBMapping,
            __db_engine, self.storage.tmp_loc, __logger)
        df_bulk_update_to_db(update_df, GHSAVulnEntryDetails, GHSAVulnEntryDetailsDf2DBMapping,
            __db_engine, self.storage.tmp_loc, __logger)
        self.storage.create_archive(self.storage.archive_files, self.storage.archive_file, True)
