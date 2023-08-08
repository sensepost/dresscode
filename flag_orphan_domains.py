# This script will flag all pages that contain a CSP with an unregistered or domain that is not found to see if it can be used to bypass CSP

import pandas as pd
import logging
from datetime import datetime
from tldextract.tldextract import extract
import json
from dashboard.utils.utils import get_config,get_headers_collection,get_orphans_collection
import re
from optparse import OptionParser

# Config logging
logging.basicConfig(filename=datetime.now().strftime('logs/flag-orphans-%Y%m%d_%H:%M:%S.log'),
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%Y%m%d_%H:%M:%S',
                    level=logging.DEBUG)

def parse_options():
    parser = OptionParser()
    parser.add_option("-e", "--environment", dest="environment",
                  help="Database Environment",  default="majestic")
    parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=False,
                  help="Be verbose")

    return parser.parse_args()



def parse_and_list_endpoints(report_to):
    # Report to has to be a dictionary with multiple groups.
    # Each group
    # If the report-to is an array, we assume is an array of groups
    endpoint_fqdns=[]
    try:
        prt = json.loads(report_to)
        try:
            if (type(prt)==list):
                for group in prt:
                    if ("endpoints" in group.keys()):
                        # There can be one (dict) or more than one endpoints (list)
                        if (type(group["endpoints"])==list):
                            for endpoint in group["endpoints"]:
                                if ("url" in endpoint.keys()):
                                    endpoint_fqdns.append(extract(endpoint["url"]))
                        else:
                            if ("url" in group["endpoints"].keys()):
                                endpoint_fqdns.append(extract(group["endpoints"]["url"]).fqdn)
            elif (type(prt)==dict):
                # If the report-to is a dictionary, we assume its a dictionary with a single group
                if ("endpoints" in prt.keys()):
                    if (type(prt["endpoints"])==list):
                        for endpoint in prt["endpoints"]:
                            endpoint_fqdns.append(extract(endpoint["url"]).fqdn)
                    else:
                        if ("url" in prt["endpoints"].keys()):
                            endpoint_fqdns.append(extract(prt["endpoints"]["url"]).fqdn)
        except Exception as e:
            print("Error understanding report-to header: %s" % prt)
            return endpoint_fqdns
    except Exception as e:
        # print("Error parsing %s. Skipping" % report_to)
        return endpoint_fqdns
    
    return endpoint_fqdns

def is_ip(d):
    return re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",d) is not None
                        
def get_allowed_domains(csp):
    allowed_domains=[]
    ignore=["*",
            "data:",
            "mediastream:",
            "blob:",
            "filesystem:"]
    for k,v in csp.items():
        if ("-src" in k):
            for value in v:
                if (value not in ignore and "'" not in value and not is_ip(value)):
                    # This should be a URI, so we append it to the list
                    allowed_domains.append(value)
    return allowed_domains

def find_affected_directives(csp,nxdomains: list):
    csp_key=csp[0]
    csp_values=csp[1]
    affected = []
    for nxdomain in nxdomains:
        if nxdomain in csp_values:
            affected.append({"directive": csp_key, "domain": nxdomain})
    return affected

def find_nxdomains(allowed_domains,nxdoms):
    intersection = list(set(allowed_domains) & set(nxdoms))
    if len(intersection)>0:
        return intersection
    else:
        return None

def main():
    (options,args)=parse_options()

    config = get_config(options.environment)
    headers_coll=get_headers_collection(config)
    orphans_coll=get_orphans_collection(config)

    filter = {"vulnerabilities.NOCSP": {'$exists': 0}}
    # n_documents = collection.count_documents(filter)
    csp_data = pd.DataFrame(headers_coll.find(filter))

    # Fix the headers column 
    # Transform all values to lower for better search 
    csp_data["headers_lower"]=csp_data["headers"].map(lambda x: dict((k.lower(), v.lower()) for k,v in x.items()))

    # Find now all the report-to headers and parse their JSON configuration
    # report_to=csp_data[csp_data["headers_lower"].map(lambda x: "report-to" in x.keys())]["headers_lower"].map(lambda x: x["report-to"])
    # Create a Serie with each row being an array of endpoint domains
    # rt_endpoints=report_to.map(parse_and_list_endpoints)
    # Now, we have a Serie of arrays, flatten with this incredible trick, the results will shock you
    # unique_rt_endpoints=list(set(rt_endpoints.explode().value_counts().keys()))
    # flds=list(set([extract(ad).domain+"."+extract(ad).suffix for ad in unique_rt_endpoints]))

    # # Now, resolve the first level domains to see if any is NXDOMAIN, oportunity to hijack
    # nxd=[]
    # for domain in flds:
    #     pd=extract(domain)
    #     fld="%s.%s" % (pd.domain, pd.suffix)
    #     # print ("Resolving %s" % tld)
    #     # Resolv the domain
    #     try:
    #         records = resolver.resolve(fld,"A")
    #         # addresses = [rec.address for rec in records]
    #     except NXDOMAIN as nxde:
    #         nxd.append({"_id": fld, "origin": "reportto", "date": datetime.now().strftime("%Y%m%d %H:%M:%S")})
    #     except NoAnswer as nae:
    #         print("No answer for TLD: %s" % fld)
    # # Insert the orphans into the db
    # if (len(nxd)>0):
    #     orphans_coll.insert_many(nxd)
    #     print("Report-To: Domains available to register: ")
    #     print(nxd)

    # Now list the sources from multiple *-src directives
    # directives=["script-src","default-src","object-src","worker-src","frame-src","media-src","font-src","style-src","connect-src","child-src","img-src"]
    csp_allowed_doms=csp_data["csp"].map(get_allowed_domains)

    nxd=[]

    # Update the list of domains that we are going to use to search in our database
    # by joining the previously resolved domains with the information we already have in our database
    db_orphans=list(orphans_coll.find({"status": "nxdomain"},{"_id":1}))
    db_nxd=list(map(lambda x: x["_id"], db_orphans))
    # Now iterate through the Series of csp_allowed_doms to detect where the previous orphan domains appear
    nxdoms=db_nxd+list(map(lambda x: x["_id"],nxd))
    # return the array of domains not registered. I find the hits by intersecting both arrays, the x and the nxdomains with the set() trick
    # If there's no intersection, return None
    flags_nxd=csp_allowed_doms.map(lambda x: find_nxdomains(x,nxdoms))
    csp_data["flags_nxd"]=flags_nxd

    # Now, push the vulnerability if it's not already there
    # Iterate throught all the csp rows that are not null in the column "flags_nxd" and push the vuln
    wname="ORPHANDOMAIN"
    for idx,row in csp_data[csp_data["flags_nxd"].notnull()].iterrows():
        # Check if the weakness already exists in the DB
        odv=headers_coll.find_one({"_id": row["_id"],"vulnerabilities.{}".format(wname): {'$exists': 1}})
        if (odv is None):
            affected_directives=map(lambda csp: find_affected_directives(csp,csp_data["flags_nxd"].iloc[idx]),row["csp"].items())
            for affected_dir in affected_directives:
                if (len(affected_dir)>0):
                    for afd in affected_dir:
                        weakness_desc=config["general"]["vulns_explanation"][wname].format(afd["domain"],afd["directive"])
                        # The weakness does not exists, push it to the array of weaknesses
                        headers_coll.update_one({"_id": row["_id"]},{'$set': {"vulnerabilities.{}".format(wname): weakness_desc}})
        else:
            logging.info("The vulnerability of %s has been preivously inserted in the DB. Skipping." % row["_id"])


if __name__ == "__main__":
    main()