"""nist/db/models.py

Author: neo154
Version: 0.1.0
Date Modified: 2024-02-05

Contains Table based information for NIST tables, including types, mappers, enumerations, and
documentation for datapoints that are being stored
"""

import enum
from datetime import date, datetime

from afk.db.models import DeclarativeBaseTable, generate_mappers
from sqlalchemy import Date, DateTime, Enum, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column


class ImpactEnum(enum.Enum):
    """Impact Enumeration"""
    NONE = 1
    LOW = 2
    PARTIAL = 3
    HIGH = 4
    COMPLETE = 5

class RecordTypeEnum(enum.Enum):
    """Record Type Enumeration"""
    Primary = 1    # pylint: disable=invalid-name
    Secondary = 2  # pylint: disable=invalid-name

class AttackVectorEnum(enum.Enum):
    """Attack vector enumeration"""
    LOCAL = 1
    ADJACENT_NETWORK = 2
    NETWORK = 3

class AttackComplexityEnum(enum.Enum):
    """Attack complexity Enumeration"""
    HIGH = 1
    MEDIUM = 2
    LOW = 3

class BaseSeverityEnum(enum.Enum):
    """Base Severity Enumeration"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

NIST_ENUMS = (ImpactEnum, RecordTypeEnum, AttackVectorEnum, AttackComplexityEnum, BaseSeverityEnum)


CVE_ID_DOC = "Uniquely identifies a CVE entry"
CVE_SRC_ID_DOC = "Identifies the originating source of a CVE entry and accompanying data"
PUBLSH_DATETIME_DOC = "Datetime that the CVE entry was published to NIST"
LST_MOD_DATETIME_DOC = "Datetime that the CVE entry was last modified in the NIST DB"
STATUS_DOC = "The current status of a CVE entry in NIST DB, like workflow"
DSCRPTN_DOC = "A short description of the vulnerability for a given CVE"
LST_UPDT_DATE_DOC = "Date that the record was last updated in DB"

class CVEEntry(DeclarativeBaseTable):
    """Entry for table in Database"""

    __tablename__ = "NIST_CVE"

    CVE_ID: Mapped[str] = mapped_column(String(16), primary_key=True, doc=CVE_ID_DOC)
    SRC_ID: Mapped[str] = mapped_column(String(60), nullable=False, doc=CVE_SRC_ID_DOC)
    PUBLSH_DATETIME: Mapped[datetime] = mapped_column(DateTime, nullable=False,
        doc=PUBLSH_DATETIME_DOC)
    LST_MOD_DATETIME: Mapped[datetime] = mapped_column(DateTime, nullable=False,
        doc=LST_MOD_DATETIME_DOC)
    STATUS: Mapped[str] = mapped_column(String(30), nullable=False, doc=STATUS_DOC)
    DSCRPTN: Mapped[str] = mapped_column(Text(5000), nullable=False, doc=DSCRPTN_DOC)
    LST_UPDT_DATETIME: Mapped[date] = mapped_column(Date, nullable=False,
        insert_default=date.today(), onupdate=date.today(), doc=LST_UPDT_DATE_DOC)

CVEEntryDB2DfMapping, CVEEntryDf2DBMapping = generate_mappers({
    'CVE_ID': 'cve_id',
    'SRC_ID': 'source_id',
    'PUBLSH_DATETIME': 'published_datetime',
    'LST_MOD_DATETIME': 'last_modified_datetime',
    'STATUS': 'status',
    'DSCRPTN': 'description'
}, CVEEntry, ['LST_UPDT_DATETIME'])


VERSION_DOC = "Version of CVSS model used for the CVSS entry"
CVSS_SRC_ID_DOC = "Originating source of a CVSS record"
TYPE_DOC = "Record type according to NIST for scoring, Pimary or Secondary"
VCTR_STR_DOC = "CVSS vector string, formats will differ based on the VERSION of CVSS"
ATTCK_VCTR_DOC = "Attack vector documented for a given vulnerability"
ATTCK_CMPLXTY_DOC = "Amount of complexity for a vulnerability"
CNFDNLTY_IMPCT_DOC = "Amount or degree of impact to confidentiality the exploitation of a "\
    + "vulnerability has"
INTGRTY_IMPCT_DOC = "Amount or degree of impact to integrity the exploitation of a "\
    + "vulnerability has"
AVLBLTY_IMPCT_DOC = "Amount or degree of impact to availability the exploitation of a "\
    + "vulnerability has"
BSE_SCR_DOC = "Base score of a vulnerability has for risk based on a CVSS record"
BSE_SEV_DOC = "Base severity of a vulnerability has for risk based on a CVSS record"
EXPLTBLTY_SCR_DOC = "Score that summarizes the ease or liklihood of a vulnerability count be "\
    + "exploited"
IMPCT_SCR_DOC = "Score that summarizes the impact of the exploitation of a vulnerability"

class CVSSEntry(DeclarativeBaseTable):
    """Entry for cve's cvss information"""

    __tablename__ = "NIST_CVSS"

    CVE_ID: Mapped[str] = mapped_column(ForeignKey('NIST_CVE.CVE_ID'), primary_key=True,
        doc=CVE_ID_DOC)
    VERSION: Mapped[str] = mapped_column(String(3), primary_key=True, doc=VERSION_DOC)
    SRC_ID: Mapped[str] = mapped_column(String(30), primary_key=True, doc=CVSS_SRC_ID_DOC)
    TYPE: Mapped[str] = mapped_column(Enum(RecordTypeEnum), primary_key=True, doc=TYPE_DOC)
    VCTR_STR: Mapped[str] = mapped_column(String(50), nullable=False, doc=VCTR_STR_DOC)
    ATTCK_VCTR: Mapped[str] = mapped_column(Enum(AttackVectorEnum),
        nullable=True, doc=ATTCK_VCTR_DOC)
    ATTCK_CMPLXTY: Mapped[str] = mapped_column(Enum(AttackComplexityEnum),
        nullable=True, doc=ATTCK_CMPLXTY_DOC)
    CNFDNLTY_IMPCT: Mapped[str] = mapped_column(Enum(ImpactEnum),
        nullable=False, doc=CNFDNLTY_IMPCT_DOC)
    INTGRTY_IMPCT: Mapped[str] = mapped_column(Enum(ImpactEnum),
        nullable=False, doc=INTGRTY_IMPCT_DOC)
    AVLBLTY_IMPCT: Mapped[str] = mapped_column(Enum(ImpactEnum),
        nullable=False, doc=AVLBLTY_IMPCT_DOC)
    BSE_SCR: Mapped[float] = mapped_column(Float(1), nullable=False, doc=BSE_SCR_DOC)
    BSE_SEV: Mapped[str] = mapped_column(Enum(BaseSeverityEnum), nullable=True, doc=BSE_SEV_DOC)
    EXPLTBLTY_SCR: Mapped[float] = mapped_column(Float(1), nullable=False, doc=EXPLTBLTY_SCR_DOC)
    IMPCT_SCR: Mapped[float] = mapped_column(Float(1), nullable=False, doc=IMPCT_SCR_DOC)
    LST_UPDT_DATETIME: Mapped[date] = mapped_column(Date, nullable=False,
        insert_default=date.today(), onupdate=date.today(), doc=LST_UPDT_DATE_DOC)

CVSSEntryDB2DfMapping, CVSSEntryDf2DBMapping = generate_mappers({
    'CVE_ID': 'cve_id',
    'VERSION': 'version',
    'SRC_ID': 'source',
    'TYPE': 'type',
    'VCTR_STR': 'vector_string',
    'ATTCK_VCTR': 'attack_vector',
    'ATTCK_CMPLXTY': 'attack_complexity',
    'CNFDNLTY_IMPCT': 'confidentiality_impact',
    'INTGRTY_IMPCT': 'integrity_impact',
    'AVLBLTY_IMPCT': 'availability_impact',
    'BSE_SCR': 'base_score',
    'BSE_SEV': 'base_severity',
    'EXPLTBLTY_SCR': 'exploitability_score',
    'IMPCT_SCR': 'impact_score'
}, CVSSEntry, ['LST_UPDT_DATETIME'])
