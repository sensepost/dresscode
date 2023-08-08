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
from datetime import datetime
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
    parser.add_option("-f", "--file", dest="file",
                  help="Input file with domain list or URL list", metavar="FILE")
    parser.add_option("-c", "--chunksize", dest="chunksize",
                  help="Chunk size (default: 1000)", type="int", default=1000)
    parser.add_option("-e", "--environment", dest="environment",
                  help="Environment name (default: majestic)", default="majestic")
    parser.add_option("-s", "--scrapeops", dest="scrapeops",
                  help="Use scrapeops random headers (default: False)", action="store_true", default=False)
    parser.add_option("-o", "--offset", dest="offset",
                  help="Offset of the input file to start the scans from (default: 0)", type="int", default=0)
    parser.add_option("-t", "--timeout", dest="timeout",
                  help="Timeout of http connections in seconds (default: 50)", type="int", default=50)
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
async def get_headers_and_resolve(session,domain: str,rank: int,resolve=True,headers=None):
    h=None
    url=schemed(domain)
    domain=domain.replace("https://","").replace("http://","")
    tld=url.split(".")[-1]
    country,continent=gir.get_tld_country_continent(tld)
    item = {"_id": "%s__%s".replace(".","_").replace("/","_") % (url,url),"url": url, "final_url": url, "date": (datetime.now().strftime("%Y%m%d %H:%M:%S")),  "headers": None, "csp": None, "cspro": None, "globalRank": rank, "tld": tld, "domain": domain}
    item["country"]={"iso_code": country, "reason": "ccTLD"}
    item["continent"]={"name": continent, "reason": "ccTLD"}

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
        else:
            async with session.get(url,allow_redirects=True,timeout=options.timeout,verify_ssl=False) as r:
                # To prevent missing information, we normalise the information by lowercasing it all 
                # We also remove the dot "." from the headers names, because MongoDB have hard times managing keys with dots in them
                sanitised_headers = {k.replace(".","§").lower(): v.lower() for k,v in r.headers.items()}
                csp,cspro=parse_csp(headers=sanitised_headers,lower=True,ro=True)
                item["headers"]=sanitised_headers
                item["csp"]=csp
                item["cspro"]=cspro
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

async def main():
    logging.debug("Reading from file %s in chunks of size %s" % (options.file, options.chunksize))
    # open db connection
    logging.debug("Connecting to the database")
    config=get_config(options.environment)
    collection = get_headers_collection(config)
    
    # Read the ranking and domains file
    input_df=pd.read_csv(options.file,names=["rank","domain"],index_col="rank")

    # Proccess the list by slices of size chunksize
    offset=options.offset
    total_inserted=0
    total_updated=0
    total_emtpy_headers=0
    while (offset < len(input_df)):
        logging.info("Polling the headers of the slice at position %s" % offset)
        chunk=input_df.iloc[offset:offset+options.chunksize]

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
            documents = await get_all_headers(session=session,urls_df=chunk,headers=req_headers)
            
            # Search for the record in the db
            updated_documents=0
            new_documents=0
            new_emtpy_headers=0
            for document in documents:
                res=collection.find_one({'_id': document["_id"]})
                if (res is not None and len(res)>0):
                    try:
                        # This record exists. If we have headers but previously these were empty, update the record with good data
                        if (len(document["headers"]) > 0):
                            if (len(res["headers"])==0):
                                logging.info("Updating headers of %s with valid values" % document["_id"])
                                collection.update_one({'_id': document["_id"]}, { '$set': {'headers': document['headers'], 'date': (datetime.now().strftime("%Y%m%d %H:%M:%S")) } })
                                updated_documents+=1
                            else:
                                logging.info("Not updating headers of %s. It already had good info in the DB." % document["domain"])
                        else:
                            logging.info("Not updating headers of %s. We got an empty headers response" % document["domain"])
                    except Exception as e:
                        logging.error("There was an error updating the headers of site %s in the database: %s" % (document["domain"],e))
                else:
                    try:
                        # Insert the new record
                        logging.info("Inserting one new site: %s" % document["_id"])
                        collection.insert_one(document)
                        new_documents+=1
                        if (document['headers']=={}):
                            new_emtpy_headers+=1
                    except Exception as e:
                        logging.error("There was an error inserting %s in the DB: %s" % (document,e))

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
    asyncio.run(main())#,debug=True)
    end = time()
    taken=end-start
    print("Time taken: %s" % round(taken,2))
