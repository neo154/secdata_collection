"""cisa/transformation.py

Author: neo154
Version: 0.1.0
Date Modified: 2024-02-05

Contains necessary data for transforming CISA data for usage from datafile or for DB
"""

import pandas as pd


def type_cisa_df(raw_df: pd.DataFrame) -> pd.DataFrame:
    """
    Runs typing required for DB interaction and DB

    :param raw_df: DataFrame of raw CISAKev data from CSV file
    :returns: DataFrame with typed data for the database
    """
    raw_df['dateAdded'] = pd.to_datetime(raw_df['dateAdded'], utc=True).dt.date
    raw_df['dueDate'] = pd.to_datetime(raw_df['dueDate'], utc=True).dt.date
    return raw_df
