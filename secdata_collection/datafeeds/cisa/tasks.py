"""cisa/tasks.py

Author: neo154
Version: 0.1.0
Date Modified: 2024-02-05

Contains the task object for CISA that are create for updating and maintaining the CISA KEV
catalogue and making it available in a DB
"""

from datetime import datetime
from logging import INFO

import pandas as pd
from afk import CredsManagerInterface, StorageConfig
from afk.db.connection import (_SupportedDialectsType, confirm_table_exists,
                               create_tables, df_bulk_insert_to_db,
                               get_table_pk_df)
from afk.task import INTERACTIVE, _defaultLogger
from sqlalchemy import delete

from secdata_collection.datafeeds.base_datafeed import (BaseDBDatafeedTask,
                                                        check_rotate)
from secdata_collection.datafeeds.cisa.api_conn import get_cisa_kev
from secdata_collection.datafeeds.cisa.db.models import (CISAKev,
                                                         KEVEntryDb2DfMapping,
                                                         KEVEntryDf2DbMapping)
from secdata_collection.datafeeds.cisa.transformation import type_cisa_df


class CISAKevDBUpdate(BaseDBDatafeedTask):
    """Task used to download and update the CISA Kev in a DB"""

    def __init__(self, db_host: str, db_dialect: _SupportedDialectsType,
            db_creds_manager: CredsManagerInterface, db_name: str=None, db_driver: str=None,
            db_port: int=None, run_type: str='testing', override: bool = False,
            storage_config: StorageConfig=None, interactive: bool=INTERACTIVE, **kwargs) -> None:
        super().__init__(db_host, db_dialect, db_creds_manager, db_name, db_driver, db_port,
            'cisa', 'cisa_kev_db', run_type, True, True, override, datetime.now(), storage_config,
            kwargs.get('logger', _defaultLogger), kwargs.get('logger_level', INFO), interactive)
        self.__request_proxies = kwargs.get('proxies')
        self.__cisa_url = "https://www.cisa.gov/sites/default/files/csv/" \
            + "known_exploited_vulnerabilities.csv"
        self.storage.archive_file = 'cisa_kev_db.tar.bz2'

    def main(self) -> None:
        """Main task for updating the CISA KEV DB and archiving info for fedelity"""
        self.check_run_conditions()
        check_rotate(self.storage.archive_file, self.override, self.logger)
        __db_engine = self.db_engine
        if not confirm_table_exists(__db_engine, CISAKev):
            self.logger.info("CISAKev table is missing")
            create_tables(CISAKev, __db_engine, self.logger)
        pk_df: pd.DataFrame = get_table_pk_df(__db_engine, CISAKev, KEVEntryDb2DfMapping)
        if pk_df.index.size > 0:
            # Need to drop entries
            with __db_engine.connect() as db_conn:
                _ = db_conn.execute(delete(CISAKev))
                db_conn.commit()
        self.logger.info("Collecting KEV data from CISA")
        tmp_file = self.storage.gen_tmpfile_ref('cisa_kev.csv')
        get_cisa_kev(self.__cisa_url, tmp_file, self.__request_proxies)
        with tmp_file.open('r') as open_file:
            recs_df = type_cisa_df(pd.read_csv(open_file))
        df_bulk_insert_to_db(recs_df, CISAKev, KEVEntryDf2DbMapping, __db_engine,
              self.storage.tmp_loc, self.logger)
        self.storage.add_to_archive_list(tmp_file)
        self.storage.create_archive(self.storage.archive_files, self.storage.archive_file, True)
