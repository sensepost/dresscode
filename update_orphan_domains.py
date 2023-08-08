# This script will update the DB collection "orphan" with orphan domains.
# All pages that contain a CSP with an unregistered or domain that is not found to see if it can be used to bypass CSP
# After this script has been executed and the collection updated you want to execute the script "flag_orphan_domains.py"
# to populate the CSP database with the weakness itself

import pandas as pd
import logging
from datetime import datetime
from tldextract.tldextract import extract
import json
from dashboard.utils.utils import get_config,get_headers_collection,get_orphans_collection
from dns.resolver import Resolver,NoAnswer,NXDOMAIN,NoNameservers
import re
from optparse import OptionParser

# Config logging
logging.basicConfig(filename=datetime.now().strftime('logs/update-orphans-%Y%m%d_%H:%M:%S.log'),
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%Y%m%d_%H:%M:%S',
                    level=logging.DEBUG)

def parse_options():
    parser = OptionParser()
    parser.add_option("-e", "--environment", dest="environment",
                  help="Database Environment",  default="majestic")
    parser.add_option("-r", "--resolvers", dest="resolvers",
                  help="List of DNS resolvers separated by comma",  default="8.8.8.8,1.1.1.1,8.8.4.4,8.26.56.26,208.67.222.222")
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

    resolver = Resolver()
    rlist = [res.strip() for res in options.resolvers.split(",")]
    resolver.nameservers=rlist # ["8.8.8.8","1.1.1.1","8.8.4.4","8.26.56.26","208.67.222.222"]

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
    unique_allowed_doms=set(csp_allowed_doms.explode().value_counts().keys())
    flds=list(set([extract(ad).domain+"."+extract(ad).suffix for ad in unique_allowed_doms]))

    nxd=[]
    exd=[]
    for domain in flds:
        parsedd=extract(domain)
        fld="%s.%s" % (parsedd.domain, parsedd.suffix)
        # Retrieve the record from the DB
        explored_domain=orphans_coll.find_one({"_id": fld})
        # First level domains that are not just alphanumeric
        if ((explored_domain is None or len(explored_domain)==0) and (re.match("^[\w\d\.-]*$",fld) is not None)):
            try:
                records = resolver.resolve(fld,"A")
                # addresses = [rec.address for rec in records]
                exd.append({"_id": fld, "status": "exists", "origin": "directive-sources", "date": datetime.now().strftime("%Y%m%d %H:%M:%S")})
            except NXDOMAIN as nxde:
                nxd.append({"_id": fld, "status": "nxdomain", "origin": "directive-sources", "date": datetime.now().strftime("%Y%m%d %H:%M:%S")})
            except NoAnswer as nae:
                print("No DNS answer for TLD: %s" % fld)
                exd.append({"_id": fld, "status": "noanswer", "origin": "directive-sources", "date": datetime.now().strftime("%Y%m%d %H:%M:%S")})
            except NoNameservers as nne:
                print("No nameservers could resolve TLD: %s" % fld)
                exd.append({"_id": fld, "status": "notresolvable", "origin": "directive-sources", "date": datetime.now().strftime("%Y%m%d %H:%M:%S")})
            except Exception as e:
                print("Exception: %s" % e)
                exd.append({"_id": fld, "status": "othererror", "origin": "directive-sources", "date": datetime.now().strftime("%Y%m%d %H:%M:%S")})
        else:
            logging.debug("First level domain %s already explored. Skipping" % fld)

    r1=r2=None
    if (len(nxd)>0):
        # Insert the orphans into the db
        r1=orphans_coll.insert_many(nxd)
        logging.info("Inserted %s orphan domains" % (len(r1.inserted_ids)))

    if (len(exd)>0):
        r2=orphans_coll.insert_many(exd)
        logging.info("Inserted %s non-orphan domains in the DB" % (len(r2.inserted_ids)))


if __name__ == "__main__":
    main()