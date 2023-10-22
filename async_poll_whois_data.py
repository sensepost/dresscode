#!/usr/bin/env python

# This script will pull data of the site and will insert into the database

import whois
import logging
from datetime import datetime
from optparse import OptionParser
import pandas as pd
from dashboard.utils.utils import get_config,get_headers_collection
import asyncio
from time import time

# Config logging
logging.basicConfig(filename=datetime.now().strftime('logs/whois-%Y%m%d_%H:%M:%S.log'),
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%Y%m%d_%H:%M:%S',
                    level=logging.DEBUG)

def parse_options():
    parser = OptionParser()
    parser.add_option("-c", "--chunksize", dest="chunksize",
                  help="Chunk size (default: 100)", type="int", default=100)
    parser.add_option("-e", "--environment", dest="environment",
                  help="Database Environment",  default="majestic")
    parser.add_option("-I", "--ip", dest="ip",
                  help="Use IPv4 for the whois query",  action='store_true', default=False)
    parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=False,
                  help="Be verbose")

    return parser.parse_args()

# Get the headers of one single URL
async def get_whois(target,ip_lookup: bool):
    item=None
    try:
        whois_resp=whois.whois(target)
        item={"target": target, "ip_lookup": ip_lookup, "whois": whois_resp}
    except TimeoutError as e:
        logging.error("Timeout when asking whois %s" % target)
    except Exception as e:
        logging.error("Unknown error when executing whois to resolve %s: %s" % (target,e))
    return item

# Async function to retrieve all the headers for a bunch of URLs
# It returns all the headers at once
async def get_whois_tasks(targets,ip_lookup: bool):
    tasks=[]
    if (ip_lookup):
        for ips in list(targets["IPv4"]):
            # for ip in ips:
            # I only need to get the whois of the first IP, not all
            # TODO: In the future, create a whois entry for each IP address
            task=asyncio.create_task(get_whois(ips[0],ip_lookup))
            tasks.append(task)
    else:
        for host in list(targets["host"]):
            task = asyncio.create_task(get_whois(host))
            tasks.append(task)
    items = await asyncio.gather(*tasks)
    return items

def update_whois(db_document,whois_result,options,collection,mapping_df):
    updated_whois=0
    if ("country" in whois_result["whois"].keys() and whois_result["whois"]['country'] is not None):
        try:
            logging.debug("Assigning the country %s to this record." % whois_result["whois"]["country"])
            collection.update_one({'_id': db_document["_id"]}, 
                                  { '$set': {'whois': {'IPv4': options.ip, 'whois_data': whois_result['whois']} , 
                                             'country': whois_result["whois"]['country'], 
                                             'continent': mapping_df[mapping_df["TLD"]==whois_result['whois']['country'].lower()].Continent.values[0]
                                            } 
                                  })
            updated_whois+=1
        except Exception as ex:
            logging.error("Error updating this record in the DB with country and continent information: %s" % ex)
    else:
        try:
            #logging.debug("Not assigning country to this record.")
            collection.update_one({'_id': db_document["_id"]}, { '$set': {'whois': { 'IPv4': options.ip, 'whois_data': whois_result['whois']} } })
            updated_whois+=1
        except Exception as ex:
            logging.error("Error updating this record withoug country information: %s" % ex)
    return updated_whois

########
# MAIN #
########

async def main():
    # Read options and make them available to all functions
    (options,args)=parse_options()

    # Get the sites stored in the DB
    logging.debug("Connecting to the database")
    config=get_config(options.environment)
    collection=get_headers_collection(config)
    # Search for CSP sites without a whois record and filter the ones that are not country TLDs
    cursor=collection.find({"whois": {'$exists': 0}},{"url":1,"_id":0,"IPv4":1})
    
    # Filter only to analyse sites with an IPv4 entry and create its cctld and host field
    csp_url_data=pd.DataFrame(list(cursor))
    csp_url_data=csp_url_data[csp_url_data["IPv4"].notnull()]
    csp_url_data["cctld"]=csp_url_data["url"].map(lambda url: url.split(".")[-1:].pop())
    csp_url_data["host"]=csp_url_data["url"].map(lambda url: url.split("/")[2:].pop())

    # Find the urls that are not country TLDs to use their whois
    mapping_df=pd.read_csv("dashboard/data/countries.tlds.csv")
    mapping_country_continent=pd.read_csv("dashboard/data/countries.continents.csv")
    # Create continent colum in the mapping
    iso_to_cont_df=pd.DataFrame(index=list(mapping_country_continent["ISO-3"]),data={"Continent": list(mapping_country_continent["Continent"])})
    mapping_df["Continent"]=mapping_df["ISO"].map(lambda x: iso_to_cont_df.loc[x].values[0] if x in iso_to_cont_df.index else None)
    # Create a DataFrame for sites with CSP but without a correspondent ccTLD to map it to a country
    csp_nocountry=csp_url_data[csp_url_data["cctld"].map(lambda cctld: cctld not in list(mapping_df.index))]

    targets=None
    if (not options.ip):
        targets=csp_nocountry[csp_nocountry["host"].notnull()]
    else:
        targets=csp_nocountry[csp_nocountry["IPv4"].notnull()]

    chunks=[]
    offset=0
    while (offset<len(targets)):
        chunks.append(targets[offset:offset+options.chunksize])
        offset+=options.chunksize

    # Now resolve the whois in chunks with aiohttp
    for chunk in chunks:
        logging.debug("Requesting whois information of the sites/IPs: %s" % chunk)
        whois_results = await get_whois_tasks(targets=chunk,ip_lookup=(options.ip))
        # Insert whois data in the DB
        # Search for the record in the db
        updated_whois=0
        for whois_result in whois_results:
            try:
                if whois_result is not None and whois_result['whois'] is not None:
                    db_document=None
                    if (not options.ip):
                        db_documents=collection.aggregate([{'$match': {'url': whois_result['target']}},{'$project': {"url":1,"_id":1,"IPv4":1,"whois":1}}])
                    else:
                        db_documents=collection.aggregate([{'$unwind': "$IPv4"},{'$project': {"url":1,"_id":1,"IPv4":1,"whois":1}},{'$match': {"IPv4": whois_result['target']}}])

                    for db_document in db_documents:
                        if (db_document is not None):
                            # This record exists. If we have headers but previously these were empty, update the record with good data
                            if (len(whois_result["whois"]) > 0):
                                if ("whois" in db_document.keys()):
                                    if (db_document["whois"] is None or len(db_document["whois"])==0):
                                        # Update the document in the DB, as it has 0 size or is None
                                        logging.debug("Updating whois field of %s (%s) with valid values" % (db_document["url"],whois_result['target']))
                                        updated_whois+=update_whois(db_document,whois_result,options,collection,mapping_df) 
                                else:
                                    # The current record do not have a "whois" field. Introduce it now
                                    logging.debug("The 'whois' field do not exists in the DB for this record. Creating it now.")
                                    updated_whois+=update_whois(db_document,whois_result,options,collection,mapping_df) 
                            else:
                                logging.debug("The new whois data is empty. Not updating whois field of %s with data: %s" % (whois_result["target"],whois_result["whois"]))
                        else:
                            # Insert the new record
                            logging.debug("The target '%s' cannot be found in the DB. Skipping." % whois_result["target"])
            except Exception as ex:
                logging.error("There was an error inserting the whois record into the database: %s - %s" % (ex,db_document))
        
        logging.info("Udated %s whois fields with valid values" % updated_whois)
        # collection.insert_many(headers,ordered=False)

if __name__ == "__main__":
    start = time()
    # Disable debug for production
    asyncio.run(main()) #, debug=True)
    end = time()
    taken=end-start
    print("Time taken: %s" % round(taken,2))