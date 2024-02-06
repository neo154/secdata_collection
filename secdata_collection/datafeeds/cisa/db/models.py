"""cisa/db/models.py

Author: neo154
Version: 0.1.0
Date Modified: 2024-02-01

Contains Table based information for NIST tables
"""

import enum
from datetime import date, datetime

from afk.db.models import DeclarativeBaseTable, generate_mappers
from sqlalchemy import Date, Enum, String
from sqlalchemy.orm import Mapped, mapped_column


class KnownRansomewareCampaignUse(enum.Enum):
    """Impact enumeration for if vuln is used in Ransomware campaign"""
    Unknown = 0  # pylint: disable=invalid-name
    Known = 1    # pylint: disable=invalid-name

class CISAKev(DeclarativeBaseTable):
    """Entry for table in Database"""

    __tablename__ = "CISA_KEV"

    CVE_ID: Mapped[str] = mapped_column(String(16), primary_key=True,
        doc="Unique identifier for vulnerability entries")
    VNDR_PRJCT: Mapped[str] = mapped_column(String(30), nullable=False,
        doc='Name of the vendor or project responsible for a product')
    PRDCT: Mapped[str] = mapped_column(String(200), nullable=False,
        doc='Name of the product that is vulnerable')
    VLN_NAME: Mapped[str] = mapped_column(String(200), nullable=False,
        doc='Name of vulnerability that is commonly used colloquially')
    CISA_ADDED_DATE: Mapped[datetime] = mapped_column(Date, nullable=False,
        doc='Date that CISA added CVE to KEV Database')
    SHRT_DSC: Mapped[str] = mapped_column(String(750), nullable=False,
        doc='Short Description of a givne CVE entry')
    REQRD_ACTN: Mapped[str] = mapped_column(String(500), nullable=False,
        doc='Text providing basic instructions on the actions required for remediation')
    DUE_DATE: Mapped[datetime] = mapped_column(Date, nullable=False,
        doc='Date that CISA requires government system to be remediated for vulnerability')
    KNWN_RNSMWR_CMPGN: Mapped[str] = mapped_column(Enum(KnownRansomewareCampaignUse),
        nullable=False,
        doc='If the CVE is Known or not known to be a part of a ransomware campaign')
    NOTES: Mapped[str] = mapped_column(String(750),  nullable=True,
        doc='Notes or related links for extra details or information about remediation')
    DB_UPDATED_DATE: Mapped[datetime] = mapped_column(Date, nullable=False,
        insert_default=date.today(), onupdate=date.today(),
        doc='Date that it was inserted into the Database')

KEVEntryDb2DfMapping, KEVEntryDf2DbMapping = generate_mappers({
    "CVE_ID": "cveID",
    "VNDR_PRJCT": "vendorProject",
    "PRDCT": "product",
    "VLN_NAME": "vulnerabilityName",
    "CISA_ADDED_DATE": "dateAdded",
    "SHRT_DSC": "shortDescription",
    "REQRD_ACTN": "requiredAction",
    "DUE_DATE": "dueDate",
    "KNWN_RNSMWR_CMPGN": "knownRansomwareCampaignUse",
    "NOTES": "notes"
}, CISAKev, ['DB_UPDATED_DATE'])
