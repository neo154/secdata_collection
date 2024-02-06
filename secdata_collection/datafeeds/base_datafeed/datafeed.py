"""datafeed.py

Author: neo154
Version: 0.1.0
Date Modified: 2024-02-01

This is the module that is responsible for declaring basic objects, definations and functions
that are going to be implemented
"""

from datetime import datetime
from logging import INFO, Logger
from typing import List, Union

from afk import BaseTask, CredsManagerInterface, Storage, StorageLocation
from afk.afk_logging import generate_logger
from afk.db.connection import _SupportedDialectsType
from afk.storage.storage_config import StorageConfig
from afk.task import INTERACTIVE, _defaultLogger
from sqlalchemy import URL, Engine, create_engine

_DEFAULT_LOGGER = generate_logger(__name__)
_DEFAULT_DB_NAME = "SEC_DATA"

_SupportedCompressionSuffixes = ['.gz', '.bz2', '.xz']
_SupportedDialects = ['mysql', 'postgresql']

def check_rotate(check_loc: StorageLocation, override: bool, logger_ref: Logger) -> None:
    """
    Checks and possibly rotates file if override is triggerd, otherwise will throw error

    :param check_loc: StorageLocation to check for existance, for example a datafile or archive
    :param override: Boolean whether or not to rotate the eixsting StorageLocation if found
    :param logger_ref: Logger object
    :returns: None
    :raises FileExistsError: If file exists and not set for an override
    """
    if check_loc.exists():
        if not override:
            raise FileExistsError(f"Cannot proceed, {check_loc} eixsts")
        check_loc.rotate(logger=logger_ref)

class Datafeed(object):
    """Base Datafeed object that will have the datafiles it collects, manages, and archives"""

    def __init__(self, storage_ref: Storage, creds_manager: CredsManagerInterface=None,
            db_creds_manager: CredsManagerInterface=None, logger_ref: Logger=_DEFAULT_LOGGER,
            compression_suffix: str='.gz') -> None:
        if compression_suffix not in _SupportedCompressionSuffixes:
            raise ValueError(f'Unrecognized compression suffix {compression_suffix}')
        self.__storage = storage_ref
        self.__logger = logger_ref
        self.__creds_manager = creds_manager
        self.__db_creds_manager = db_creds_manager
        self.__compression_suffix = compression_suffix
        self.__datafiles = []

    @property
    def storage(self) -> Storage:
        """Storage for the datafeed"""
        return self.__storage

    @property
    def logger(self) -> Logger:
        """Logger for datafeed interactions"""
        return self.__logger

    @property
    def datafiles(self) -> List[StorageLocation]:
        """Gets and returns the datafiles"""
        return self.__datafiles

    @property
    def creds_manager(self) -> CredsManagerInterface:
        """Gets creds manager for this datafeed"""
        return self.__creds_manager

    @property
    def db_creds_manager(self) -> CredsManagerInterface:
        """Gets creds manager specific for DB"""
        return self.__db_creds_manager

    @property
    def compression_suffix(self) -> str:
        """Gets ending suffix for compression"""
        return self.__compression_suffix

    def add_datafile(self, new_datafiles: Union[StorageLocation, List[StorageLocation]]) -> None:
        """
        Adds datafile references for a single or multiple Storage Locations

        :param new_datafiles: StorageLocation or List of StorageLocations to add as a datafile
                                refernce
        :returns: None
        """
        if not isinstance(new_datafiles, list):
            new_datafiles = [new_datafiles]
        self.__datafiles += new_datafiles

class BaseDBDatafeedTask(BaseTask):
    """Base datafeed task for databases"""

    def __init__(self, db_host: str, db_dialect: _SupportedDialectsType,
            db_creds_manager: CredsManagerInterface, db_name: str=None, db_driver: str=None,
            db_port: int=None, task_type: str='generic_tasktype',
            task_name: str='generic_taskname', run_type: str='testing', has_mutex: bool=True,
            has_archive: bool=True, override: bool=False, run_date: datetime=datetime.now(),
            storage_config: StorageConfig=None, logger: Logger=_defaultLogger, log_level: int=INFO,
            interactive: bool=INTERACTIVE) -> None:
        super().__init__(task_type, task_name, run_type, has_mutex, has_archive, override,
            run_date, storage_config, logger, log_level, interactive)
        db_dialect_str = db_dialect
        if db_driver is not None:
            db_dialect_str += f'+{db_driver}'
        self.__db_dialect_str = db_dialect_str
        self.__db_user = db_creds_manager.get_username()
        self.__db_passwd = db_creds_manager.get_password()
        self.__db_host = db_host
        self.__db_port = db_port
        if db_name is None:
            db_name = _DEFAULT_DB_NAME
        self.__db_name = db_name
        self.__db_engine = None

    @property
    def db_engine(self) -> Engine:
        """Engine for Database datafeed tasks"""
        if self.__db_engine is None:
            self.__db_engine = create_engine(URL.create(
                self.__db_dialect_str,
                username=self.__db_user,
                password=self.__db_passwd,
                host=self.__db_host,
                database=self.__db_name,
                port=self.__db_port
            ))
        return self.__db_engine
