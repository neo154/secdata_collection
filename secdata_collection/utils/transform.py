"""utils/transform.py

Author: neo154
Version: 0.1.0
Date Modified: 2024-02-01

This is a common library for transformation operations
"""

from typing import List

from afk import StorageLocation
from afk.utils.fs_ops import resolve_open_write_method

def consolidate_partial_datafiles(dest_loc: StorageLocation,
        raw_files: List[StorageLocation]) -> None:
    """
    Consolidates multiple parsed CSV files into a single file

    :param dest_loc: StorageLocation to store the consolidate data in
    :param raw_files: List of StorageLocation objects that contain the parsed CSV files
    :returns: None
    :raises: FileExistsError if dest_loc already exists
    """
    if dest_loc.exists():
        raise FileExistsError(f"Provided destination {dest_loc}, taken")
    with resolve_open_write_method(dest_loc, 'w') as open_dest:
        with raw_files[0].open('rb') as header_ref:
            _ = open_dest.write(header_ref.readline())
        for raw_file in raw_files:
            with raw_file.open('rb') as data_ref:
                _ = data_ref.readline()
                for line in data_ref.readlines():
                    _ = open_dest.write(line)
