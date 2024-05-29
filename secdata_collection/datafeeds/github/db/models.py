"""github/db/models.py

Author: neo154
Version: 0.1.0
Date Modified: 2024-05-28

Contains model information of github related security information
"""


import enum
from datetime import datetime

from afk.db.models import DeclarativeBaseTable, generate_mappers
from sqlalchemy import DateTime, Enum, ForeignKey, String, Text, Float
from sqlalchemy.orm import Mapped, mapped_column


class GHSASeverity(enum.Enum):
    """Impact Enumeration"""
    LOW = 0
    MODERATE = 1
    HIGH = 2
    CRITICAL = 3

ID_DOC = "Uniique identifier for a given GitHub Security Advisory"
ORIGN_DOC = "String identifying where an advisory oringated from as a source"
PBLSHD_TMSTMP_DOC = "Datetime that this adivsory was published"
DESC_DOC = "Description of the Github Advisory"
SEV_DOC = "Severity of the Advisory"
SMMRY_DOC = "Summary of the Advisory"
UPDT_TMSTMP_DOC = "Datetime of when the Github Advisory was last updated"
CLSSFCTN_DOC = "Classification of a given Github Security Advisory"
CVSS_SCR_DOC = "CVSS Score of an advisory"
CVSS_VSTR_DOC = "String vector that was used to calculate the CVSS score"

class GHSAEntry(DeclarativeBaseTable):
    """Entry for table in Database"""

    __tablename__ = "GHSA_ENTRY"

    ID: Mapped[str] = mapped_column(String(25), primary_key=True, doc=ID_DOC)
    ORIGN: Mapped[str] = mapped_column(String(16), nullable=False, doc=ORIGN_DOC)
    PBLSHD_TMSTMP: Mapped[datetime] = mapped_column(DateTime, nullable=False, doc=PBLSHD_TMSTMP_DOC)
    DESC: Mapped[str] = mapped_column(Text(40000), nullable=False, doc=DESC_DOC)
    SEV: Mapped[str] = mapped_column(Enum(GHSASeverity), nullable=False, doc=SEV_DOC)
    SMMRY: Mapped[str] = mapped_column(Text(300), nullable=False, doc=SMMRY_DOC)
    UPDT_TMSTMP: Mapped[datetime] = mapped_column(DateTime, nullable=False, doc=UPDT_TMSTMP_DOC)
    CLSSFCTN: Mapped[str] = mapped_column(String(16), nullable=False, doc=CLSSFCTN_DOC)
    CVSS_SCR: Mapped[str] = mapped_column(Float(1), nullable=True, doc=CVSS_SCR_DOC)
    CVSS_VSTR: Mapped[str] = mapped_column(String(100), nullable=True,
        doc=CVSS_VSTR_DOC)

GHSAEntryDB2DfMapping, GHSAEntryDf2DBMapping = generate_mappers({
    'ID': 'ghsa_id',
    'ORIGN': 'origin',
    'PBLSHD_TMSTMP': 'published_at',
    'DESC': 'description',
    'SEV': 'severity',
    'SMMRY': 'summary',
    'UPDT_TMSTMP': 'updated_at',
    'CLSSFCTN': 'classification',
    'CVSS_SCR': 'cvss_score',
    'CVSS_VSTR': 'cvss_vector_string'
}, GHSAEntry)


ID_TYP_DOC = "Type of Vuln identifier"
VULN_ID_DOC = "Unique identifier for the type of vuln that a GHSA maps to"

class GHSAVulnEntry(DeclarativeBaseTable):
    """Entry for table in Database"""

    __tablename__ = "GHSA_VULN_ENTRY"

    VULN_ID: Mapped[datetime] = mapped_column(String(25), primary_key=True, doc=VULN_ID_DOC)
    GHSA_ID: Mapped[str] = mapped_column(ForeignKey('GHSA_ENTRY.ID'), primary_key=True, doc=ID_DOC)
    ID_TYP: Mapped[str] = mapped_column(String(16), nullable=False, doc=ID_TYP_DOC)

GHSAVulnEntryDB2DfMapping, GHSAVulnEntryDf2DBMapping = generate_mappers({
    'VULN_ID': 'identifier',
    'GHSA_ID': 'ghsa_id',
    'ID_TYP': 'identifier_type'
}, GHSAVulnEntry)

PCKG_NM_DOC = "Name of a package that is impacted by a GHSA"
PCKG_ECOSYSTM_DOC = "Ecosystem or type of package impacted by a GHSA"
VLN_V_RNG_DOC = "The version ranges that are impacted by a GSHA"
FRST_PTCH_V_DOC = "The first patched version to fix aa GHSA"
UPDTD_AT_DOC = "The last datetime that details of a vuln for GHSA was updated"

class GHSAVulnEntryDetails(DeclarativeBaseTable):
    """GHSA Vulnerability details such as impacted packages, versions and patches"""

    __tablename__ = "GHSA_VULN_ENTRY_DTLS"

    GHSA_ID: Mapped[str] = mapped_column(ForeignKey('GHSA_ENTRY.ID'), primary_key=True, doc=ID_DOC)
    SEV: Mapped[str] = mapped_column(Enum(GHSASeverity), nullable=False, doc=SEV_DOC)
    PCKG_NM: Mapped[str] = mapped_column(String(120), primary_key=True, doc=PCKG_NM_DOC)
    PCKG_ECOSYSTM: Mapped[str] = mapped_column(String(20), primary_key=True, doc=PCKG_ECOSYSTM_DOC)
    VLN_V_RNG: Mapped[str] = mapped_column(String(100), primary_key=True, doc=VLN_V_RNG_DOC)
    FRST_PTCH_V: Mapped[str] = mapped_column(String(50), nullable=True, doc=FRST_PTCH_V_DOC)
    UPDTD_AT: Mapped[str] = mapped_column(DateTime, nullable=False, doc=UPDTD_AT_DOC)

GHSAVulnEntryDetailsDB2DfMapping, GHSAVulnEntryDetailsDf2DBMapping = generate_mappers({
    'GHSA_ID': 'ghsa_id',
    'SEV': 'severity',
    'PCKG_NM': 'package_name',
    'PCKG_ECOSYSTM': 'package_ecosystem',
    'VLN_V_RNG': 'vuln_version_range',
    'FRST_PTCH_V': 'first_patched_version',
    'UPDTD_AT': 'updated_at'
}, GHSAVulnEntryDetails)
