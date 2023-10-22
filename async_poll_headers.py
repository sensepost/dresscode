#!/usr/bin/env python

# This script will receive a list of sites and retrieve all their headers asyncronouysly
# Then, the headers will be stored in the local MongoDB

import aiohttp
import asyncio
import requests
import random
from asyncio.exceptions import TimeoutError
from urllib.parse import urlparse
from optparse import OptionParser
import logging
from dashboard.utils.utils import get_config,get_headers_collection,parse_csp
from time import time
from datetime import datetime, timezone
import pandas as pd
from dns.resolver import Resolver,NoAnswer
from dns.exception import DNSException
from tldgeoip_resolver import TLDIPResolver

resolver = Resolver()
resolver.nameservers=["8.8.8.8","1.1.1.1","8.8.4.4","8.26.56.26","208.67.222.222"]

logging.basicConfig(filename=datetime.now().strftime('logs/pollheaders-%Y%m%d_%H:%M:%S.log'),
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%Y%m%d_%H:%M:%S',
                    level=logging.INFO)

def parse_options():
    parser = OptionParser()
    parser.add_option("-f", "--file", 
                      dest="file",
                      help="Input file with domain list or URL list", 
                      metavar="FILE")
    parser.add_option("-c", "--chunksize", 
                      dest="chunksize",
                      help="Chunk size (default: 1000)", 
                      type="int", 
                      default=1000)
    parser.add_option("-e", "--environment", 
                      dest="environment",
                      help="Environment name (default: majestic)", 
                      default="majestic")
    parser.add_option("-s", "--scrapeops", 
                      dest="scrapeops",
                      help="Use scrapeops random headers (default: False)", 
                      action="store_true", 
                      default=False)
    parser.add_option("-o", "--offset", 
                      dest="offset",
                      help="Offset of the input file to start the scans from (default: 0)", 
                      type="int", 
                      default=0)
    parser.add_option("-t", "--timeout", 
                      dest="timeout",
                      help="Timeout of http connections in seconds (default: 50)", 
                      type="int", 
                      default=50)
    parser.add_option("-E", "--no-new-empty", 
                      action="store_true",
                      dest="nonewempty",
                      default=False,
                      help="Do not create the new scan record if we could not connect to the site and as result, we have empty headers")
    parser.add_option("-O", "--overwrite", 
                      action="store_true",
                      dest="overwrite",
                      default=False,
                      help="Overwrite the last header scan results in the DB instead of creating a new record")
    parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=False,
                  help="Be verbose")

    return parser.parse_args()

# Read options and make them available to all functions
(options,args)=parse_options()
# Create a GeoIPResolver object to be used by all threads of the async proccess and prevent creating a GeoIP reader for each
# I'm not sure this is a good idea, but its 23:00 and I'm tired
gir = TLDIPResolver(options.environment)

# Get the headers of one single URL
async def get_headers_and_resolve(session,domain: str,rank: int = 9999999,resolve=True,headers=None):
    h=None
    url=schemed(domain)
    domain=domain.replace("https://","").replace("http://","")
    tld=url.split(".")[-1]
    country,continent=gir.get_tld_country_continent(tld)
    item = {
        "_id": "%s__%s".replace(".","_").replace("/","_") % (url,url), 
        "url": url, 
        "final_url": url, 
        "host": domain, 
        "tld": tld ,  
        "date": datetime.now(tz=timezone.utc),  
        "headers": None, 
        "csp": None, 
        "cspro": None, 
        "globalRank": rank, 
        "weaknesses": None,
        "country": {"iso_code": country, "reason": "ccTLD"},
        "continent": {"name": continent, "reason": "ccTLD"},
        "IPv4": None
    }

    # Use a random header set from scrapeops
    if (headers is not None):
        h=headers["result"][random.randrange(0,len(headers))]

    try:
        if (h is not None):
            async with session.get(url,allow_redirects=True,verify_ssl=False,headers=h) as r:
                # To prevent missing information, we normalise the information by lowercasing it all 
                # We also remove the dot "." from the headers names, because MongoDB have hard times managing keys with dots in them
                sanitised_headers = {k.replace(".","§").lower(): v.lower() for k,v in r.headers.items()}
                csp,cspro=parse_csp(headers=sanitised_headers,lower=True,ro=True)
                item["headers"]=sanitised_headers
                item["csp"]=csp
                item["cspro"]=cspro
                if ((str(r.url)) != url):
                    item["final_url"]=str(r.url)
                    item["_id"] = "%s__%s".replace(".","_").replace("/","_") % (url,item["final_url"])
        else:
            async with session.get(url,allow_redirects=True,timeout=options.timeout,verify_ssl=False) as r:
                # To prevent missing information, we normalise the information by lowercasing it all 
                # We also remove the dot "." from the headers names, because MongoDB have hard times managing keys with dots in them
                sanitised_headers = {k.replace(".","§").lower(): v.lower() for k,v in r.headers.items()}
                csp,cspro=parse_csp(headers=sanitised_headers,lower=True,ro=True)
                item["headers"]=sanitised_headers
                item["csp"]=csp
                item["cspro"]=cspro
                if ((str(r.url)) != url):
                    item["final_url"]=str(r.url)
                    item["_id"] = "%s__%s".replace(".","_").replace("/","_") % (url,item["final_url"])

    except TimeoutError as e:
        logging.error("Timeout when connecting to %s: %s" % (url,e))
    except Exception as e:
        logging.error("Unknown error when connecting to %s: %s" % (url,e))
    
    # Now resolve the domain name to their IP addresses
    if (resolve):
        addresses=[]
        try:
            records = resolver.resolve(domain,"A")
            addresses = [rec.address for rec in records]
        except DNSException as e:
            logging.error("There was an error resolving the domain %s" % domain)
        except Exception as e:
            logging.error("Error resolving %s: %s" % (domain,e))

        item["IPv4"]=addresses
        if (item["country"]["iso_code"] is None):
            # Now, we can allocate a country and a continent to this entry
            # for address in addresses:
            # No need for being exaustive, I'll just pick the first IP address of the list
            country=continent="Unknown" 
            if (len(addresses)>0):
                country,continent=gir.get_ip_country_continent(addresses[0])
            # Create the country and continent elements of the object 
            item["country"]={"iso_code": country, "reason": "IPv4"}
            item["continent"]={"name": continent, "reason": "IPv4"}

    return item

# Async function to retrieve all the headers for a bunch of URLs
# It returns all the headers at once
async def get_all_headers(session, urls_df: pd.DataFrame,headers=None):
    tasks=[]
    for idx,row in urls_df.iterrows():
        task = asyncio.create_task(get_headers_and_resolve(session,row.domain,idx,headers=headers))
        tasks.append(task)
    items = await asyncio.gather(*tasks)
    return items

def schemed(domain):
    dp = urlparse(domain)
    if (dp.scheme is None or len(dp.scheme)==0):
        # Scan the target for port 80 or 443 open
        # return get_http(domain)
        return "https://%s" % domain
    return domain

def update_last_scan(collection, last_scan: dict, scan_result, db_document):
    # Save the lastscan scan date
    last_scan["headers"]=scan_result["headers"]
    last_scan["date"]=scan_result["date"]
    last_scan["weaknesses"]=scan_result["weaknesses"] # Reset the weaknesses to None, as the headers might have changed
    # lastscan["whois"]=None # Should I delete the whois? It takes so much time to query that I feel sad to destroy if it's already populated
    # To update only one element in the array
    # https://www.mongodb.com/docs/drivers/node/current/fundamentals/crud/write-operations/embedded-arrays/
    last_scan["IPv4"]=scan_result["IPv4"]
    last_scan["country"]=scan_result["country"]
    last_scan["continent"]=scan_result["continent"]
    last_scan["csp"]=scan_result["csp"]
    last_scan["cspro"]=scan_result["cspro"]
    collection.replace_one(
        {'_id': scan_result['_id']},
        db_document
    )

def insert_new_document(collection, scan_result):
    new_entry={
        "_id": scan_result["_id"], 
        "url": scan_result["url"], 
        "final_url": scan_result["final_url"], 
        "host": scan_result["host"], 
        "tld": scan_result["tld"] ,
        "country": scan_result["country"], 
        "continent": scan_result["continent"] ,
        "scans": [
            {
                "date": scan_result["date"],
                "headers": scan_result["headers"],
                "weaknesses": scan_result["weaknesses"],
                "IPv4": scan_result["IPv4"],
                # Not updating the whois record
                "globalRank": scan_result["globalRank"],
                "csp": scan_result["csp"],
                "cspro": scan_result["cspro"],
            }
        ]
    }
    collection.insert_one(new_entry)

def new_scan_record(collection, scan_result: dict,db_document):
    # We add a new record to the scans array
    # reshape the document we just got of the Internet
    new_scan={
        "date": scan_result["date"],
        "headers": scan_result["headers"],
        "weaknesses": scan_result["weaknesses"],
        "IPv4": scan_result["IPv4"],
        # Not updating the whois record
        "globalRank": scan_result["globalRank"],
        "csp": scan_result["csp"],
        "cspro": scan_result["cspro"],
    }
    # It may happen that the document pulled from DB don't have the "scans" array of DB 2.0
    if ("scans" in db_document):
        logging.debug("The document '%s' have a 'scans' array in the DB. Appending the new scan it." % db_document["_id"])
        db_document["scans"].append(new_scan)
    else:
        logging.debug("The document '%s' do not have a 'scans' array in the DB. Creating it." % db_document["_id"])
        db_document["scans"]=[new_scan]

    # Update in the DB
    collection.replace_one(
        {'_id': scan_result['_id']},
        db_document
    )

async def main():
    logging.debug("Reading from file %s in chunks of size %s" % (options.file, options.chunksize))
    # open db connection
    logging.debug("Connecting to the database")
    config=get_config(options.environment)
    collection = get_headers_collection(config)
    
    # Read the ranking and domains file
    # TODO: Use the "skiprows" parameter of this method to save memory as well
    input_df=pd.read_csv(options.file,names=["rank","domain"],index_col="rank")

    # Proccess the list by slices of size chunksize
    offset=options.offset
    total_inserted=0
    total_updated=0
    total_emtpy_headers=0
    while (offset < len(input_df)):
        logging.info("Polling the headers of the slice at position %s" % offset)
        chunk=input_df.iloc[offset:offset+options.chunksize]
        # To save some memory, remove the rows moved to "chunk" from the input_df dataframe
        input_df.drop(input_df.iloc[offset:offset+options.chunksize].index,inplace=True)

        # Get a different set of headers for each chunk
        req_headers=None
        if (options.scrapeops):
            response = requests.get(
                url='https://headers.scrapeops.io/v1/browser-headers',
                params={
                    'api_key': config["general"]["scrapeops"],
                    'num_headers': '4'}
            )
            req_headers=response.json()

        # Now, asyncio http
        # Creating this session_timeout object because I get many timeouts when scanning now
        session_timeout = aiohttp.ClientTimeout(total=options.timeout*1.5,sock_connect=options.timeout,sock_read=options.timeout)
        async with aiohttp.ClientSession(timeout=session_timeout,version=aiohttp.http.HttpVersion11) as session:
            logging.debug("Requesting headers of the sites: %s" % list(chunk.domain))
            # HEADS UP: This function returns an array of documents. 
            # Each document is a dictionary without the "scans" array the DB currently has.
            # It is a "plain" view of this specific scan and it has to be transformed to match the DB schema that I want to have on insertion time
            scan_results = await get_all_headers(session=session,urls_df=chunk,headers=req_headers)
            
            # Search for the record in the db
            updated_documents=0
            new_documents=0
            new_emtpy_headers=0
            for scan_result in scan_results:
                db_document=collection.find_one({'_id': scan_result["_id"]})
                if (db_document is not None):
                    try:
                        # v2.0 - The software will insert a new snapshot of the headers within the "scans" array
                        if (options.overwrite):
                            if ("scans" in db_document):
                                # If the user chose to overwrite the last scans results:
                                db_document_scans = db_document["scans"]
                                if (len(db_document_scans) > 0):
                                    # Pick the most recent scan from the array of scans
                                    last_scan=max(db_document_scans,key=lambda x: x["date"])
                                    # This record exists. If we have headers but previously these were empty, update the record with good data
                                    new_headers=scan_result["headers"]
                                    previous_headers=last_scan["headers"]
                                    if (new_headers is not None and len(new_headers) > 0):
                                        # The previous headers were not populated last time, so we populate them now
                                        if (previous_headers is not None and len(previous_headers)==0):
                                            logging.info("Updating most recent scan headers of %s with valid values from this scan" % scan_result["_id"])
                                            update_last_scan(collection, last_scan, scan_result, db_document)
                                            updated_documents+=1
                                        else:
                                            logging.info("Not updating headers of '%s'. It was already populated." % scan_result["_id"])
                                    else:
                                        logging.info("Not updating headers of %s. We got an empty headers response" % scan_result["_id"])
                            else:
                                logging.error("The record with _id '%s' does not have a 'scans' array" % scan_result["_id"])
                        else:
                            # Check if we want new empty records or not
                            if (scan_result["headers"] is None or len(scan_result["headers"])==0):
                                if (not options.nonewempty):
                                    new_scan_record(collection, scan_result ,db_document)
                                    updated_documents+=1
                                    logging.debug("The new headers of '%s' were empty but we forced adding them to the new scans of the site." % scan_result["_id"])
                                else:
                                    logging.debug("The new headers of '%s' are empty. Not adding a new empty scan to the DB." % scan_result["_id"])
                            else:
                                new_scan_record(collection, scan_result ,db_document)
                                updated_documents+=1
                                logging.debug("The headers of '%s' were not empty. Adding a new scan item." % scan_result["_id"])
                        
                    except Exception as e:
                        logging.error("There was an error updating the headers of site %s in the database: %s" % (scan_result["host"],e))
                else:
                    try:
                        # Insert the new record
                        logging.info("Inserting one new site: %s" % scan_result["_id"])
                        insert_new_document(collection, scan_result)
                        new_documents+=1
                        if (scan_result["headers"]=={} or scan_result["headers"] is None):
                            new_emtpy_headers+=1

                    except Exception as e:
                        logging.error("There was an error inserting %s in the DB: %s" % (scan_result["_id"],e))

            logging.info("Udated %s headers with valid values" % updated_documents)
            logging.info("Inserted %s new documents (%s with empty headers)" % (new_documents,new_emtpy_headers))
        
        offset+=len(chunk)
        total_inserted+=new_documents
        total_updated+=updated_documents
        total_emtpy_headers+=new_emtpy_headers

        logging.info("Total Inserted documents: %s" % total_inserted)
        logging.info("Total Updated documents: %s" % total_updated)
        logging.info("Total Empty Headers: %s" % total_emtpy_headers)

    # Summary of all operations 
    logging.info("Inserted documents: %s" % total_inserted)
    logging.info("Updated documents: %s" % total_updated)

if __name__ == "__main__":
    start = time()
    # WARNING: Change the debug for production purposes
    asyncio.run(main()) # ,debug=True)
    end = time()
    taken=end-start
    print("Time taken: %s" % round(taken,2))
