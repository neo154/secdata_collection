"""cisa_kev.py

Author: neo154
Version: 0.1.0
Date Modified: 2024-02-05

This is the module that is responsible for downloading and manging CISA datafeed to the rest
of the system for analysis
"""

from logging import Logger
from typing import Dict

from afk import CredsManagerInterface, Storage
from afk.afk_logging import generate_logger
from afk.utils.fs_ops import compress_file

from secdata_collection.datafeeds.base_datafeed import Datafeed, check_rotate
from secdata_collection.datafeeds.base_datafeed.datafeed import _DEFAULT_LOGGER
from secdata_collection.datafeeds.cisa.api_conn import get_cisa_kev

_DEFAULT_LOGGER = generate_logger(__name__)


class CISAKevDataFeed(Datafeed):  # pylint: disable=inherit-non-class
    """CISA KEV Datafeed object that will have the datafiles it collects, manages, and archives"""


    def __init__(self, storage_ref: Storage, cisa_url: str=None,
            db_creds_manager: CredsManagerInterface=None,
            logger_ref: Logger=_DEFAULT_LOGGER) -> None:
        super().__init__(storage_ref, None, db_creds_manager, logger_ref)
        if cisa_url is None:
            cisa_url = "https://www.cisa.gov/sites/default/files/csv/" \
                + "known_exploited_vulnerabilities.csv"
        self.__cisa_url = cisa_url
        self.__kev_datafile = self.storage.gen_datafile_ref('cisa_kev.csv.bz2')
        self.add_datafile(self.__kev_datafile)

    def get_kev_file(self, proxies: Dict=None, override: bool=False) -> None:
        """
        Gets kev file from CISA and stores full file contents in datafile for loading

        :param proxies: Dictionary of proxy references if needed
        :param override: Boolean of whether the datafile needs to be overriden and rotated
        :returns: None
        """
        check_rotate(self.__kev_datafile, override, self.logger)
        self.logger.info("Collecting KEV data from CISA")
        tmp_file = self.storage.gen_tmpfile_ref('cisa_kev.csv')
        get_cisa_kev(self.__cisa_url, tmp_file, proxies)
        compress_file(tmp_file, self.__kev_datafile, self.logger)
