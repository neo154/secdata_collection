"""utils/transform.py

Author: neo154
Version: 0.1.1
Date Modified: 2024-05-29

This is a common library for transformation operations
"""

from logging import Logger
from typing import Iterable, List, Tuple

import pandas as pd

from afk import StorageLocation
from afk.afk_logging import generate_logger
from afk.utils.fs_ops import resolve_open_write_method

_DEFAULT_LOGGER = generate_logger(__name__)

def _check_req_cols(cols: List[str], p_df: pd.DataFrame) -> None:
    """
    Checks for required columns in dataframe

    :param cols: List of strings of names of columns that should be in given DataFrame
    :param p_df: DataFrame being searched
    :returns: None
    :raises: RuntimeError if there's missing columns that would be required otherwise
    """
    missing_cols: List[str] = []
    for col in cols:
        if col not in p_df:
            missing_cols.append(col)
    if missing_cols:
        raise RuntimeError(f"Missing columns in dataframe: {missing_cols}")

def consolidate_partial_datafiles(dest_loc: StorageLocation, raw_files: Iterable[StorageLocation],
        logger_ref: Logger=_DEFAULT_LOGGER) -> None:
    """
    Consolidates multiple parsed CSV files into a single file

    :param dest_loc: StorageLocation to store the consolidate data in
    :param raw_files: List of StorageLocation objects that contain the parsed CSV files
    :param logger_ref: Logger
    :returns: None
    :raises: FileExistsError if dest_loc already exists
    """
    if dest_loc.exists():
        raise FileExistsError(f"Provided destination {dest_loc}, taken")
    tmp_loc: StorageLocation = dest_loc.parent.join_loc(f'tmp_{dest_loc.name}')
    if not tmp_loc.parent.exists():
        tmp_loc.parent.mkdir(parents=True)
    try:
        with resolve_open_write_method(tmp_loc, 'wb') as open_dest:
            with raw_files[0].open('rb') as header_ref:
                _ = open_dest.write(header_ref.readline())
            for raw_file in raw_files:
                with raw_file.open('rb') as data_ref:
                    _ = data_ref.readline()
                    for line in data_ref.readlines():
                        _ = open_dest.write(line)
    except Exception as exc:
        logger_ref.warning("Issue during consolidation of files, cleaning up tmp file")
        tmp_loc.delete(True, logger=logger_ref)
        raise exc
    tmp_loc.move(dest_loc, logger_ref)

def get_updates_from_df(db_df: pd.DataFrame, p_df: pd.DataFrame, pk_cols: List[str]
        ) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Dumbish function that tries to get changes and new records from a single DataFrame and
    a given DataFrame in the database. It assumes that the database data and provided new
    DataFrame both are analysis ready or at minimum comparable to identify new and updates

    :param db_df: DataFrame originating from database
    :param p_df: DataFrame from originating data source that is to be compared to DB DF
    :param pk_cols: List or strings that are the primary key columns between DataFrames
    :returns: Tuple of New records DataFrame and updated records DataFrame
    """
    _check_req_cols(pk_cols, p_df)
    _check_req_cols(pk_cols, db_df)
    p_m_index = pd.MultiIndex.from_frame(p_df[pk_cols])
    db_m_index = pd.MultiIndex.from_frame(db_df[pk_cols])
    record_found_v = p_m_index.isin(db_m_index)
    orig_found_v = db_m_index.isin(p_m_index)
    new_df = p_df[ ~record_found_v ]
    poss_update_df = p_df[ record_found_v ].sort_values(pk_cols).reset_index().drop(columns='index')
    orig_df = db_df[ orig_found_v ].sort_values(pk_cols).reset_index().drop(columns='index')
    updates_recs_df = poss_update_df.loc[
        poss_update_df.compare(orig_df[poss_update_df.columns.to_list()]).index ].reset_index()\
            .drop(columns='index')
    return new_df, updates_recs_df
