from mongoengine import Document, EmbeddedDocument, connect
from mongoengine import  StringField, DateField, ListField, DictField, EmbeddedDocumentField, EnumField, IntField, ObjectIdField
from datetime import datetime,timezone
from enum import Enum

###########################
######### ORPHANS #########
###########################

class Scan(EmbeddedDocument):
    date = DateField(default=datetime.now(tz=timezone.utc))
    headers = DictField(default={}) 
    csp = DictField(default={})
    cspro = DictField(default={})
    globalRank = IntField(default=9999999)
    IPv4 = ListField(StringField(max_length=15)) # An IPv4 can have a maximum of 15 characters
    weaknesses = DictField(default={})# MapField(EmbeddedDocumentField(Vulnerability))
    whois = DictField(default={})

# For DB schema 3.0, move country and continent to a single Document "geo"
class Country(EmbeddedDocument):
    iso_code = StringField(max_length=3)
    reason = StringField()

class Continent(EmbeddedDocument):
    name = StringField()
    reason = StringField()

def site_id_validation(id: str):
    return True

class Site(Document):
    id = StringField(required=True, primary_key=True) #,validation=site_id_validation)
    url = StringField(required=True)
    final_url = StringField(required=True)
    host = StringField()
    tld = StringField()
    scans = ListField(EmbeddedDocumentField(Scan))
    country = EmbeddedDocumentField(Country)
    continent = EmbeddedDocumentField(Continent)

    meta = {'collection': 'header_scans'}


###########################
######### ORPHANS #########
###########################

class OrphanOrigin(Enum):
    CSPREPORTTO='csp-reportto'
    CSPDIRECTIVE='directive-sources'
    SCANNING='site-scanning'
    OTHER='other'

class DomainStatus(Enum):
    NXDOMAIN='nxdomain'
    NOTREGISTERED='noregistered'
    EXISTS="exists"
    NOANSWER="noanswer"
    NONS="nonameservers"
    UNKNOWN="unknown"
    OTHER="other"

class Orphan(Document):
    fld = StringField(required=True, primary_key=True)
    date = DateField(default=datetime.now(tz=timezone.utc))
    origin = EnumField(OrphanOrigin)
    status = EnumField(DomainStatus)

