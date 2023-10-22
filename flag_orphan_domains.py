# This script will update the DB collection "orphan" with orphan domains.
# All pages that contain a CSP with an unregistered or domain that is not found to see if it can be used to bypass CSP
# After this script has been executed and the collection updated you want to execute the script "flag_orphan_domains.py"
# to populate the CSP database with the weakness itself

import pandas as pd
import logging
from datetime import datetime,timezone
from tldextract.tldextract import extract
from dashboard.utils.utils import get_config,get_headers_collection,get_orphans_collection
from utils.utils import connect_db
from dns.resolver import Resolver,NoAnswer,NXDOMAIN,NoNameservers
import re
from optparse import OptionParser
import threading
from collections import Counter
from schema.schema import OrphanOrigin,DomainStatus,Orphan,Site,Scan
from whois import whois
from whois.parser import PywhoisError


# Config logging
logging.basicConfig(filename=datetime.now().strftime('logs/update-orphans-%Y%m%d_%H:%M:%S.log'),
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%Y%m%d_%H:%M:%S',
                    level=logging.DEBUG)

def p(v):
    return [res.strip() for res in v.split(",")]

def parse_resolvers(option, opt, value, parser):
    setattr(parser.values,option.dest, p(value) )

def parse_options():
    parser = OptionParser()
    parser.add_option("-e", "--environment", dest="environment",
                  help="Database Environment",  default="majestic")
    parser.add_option("-r", "--resolvers", 
                      dest="resolvers",
                      help="List of DNS resolvers separated by comma",  
                      default=['8.8.8.8','1.1.1.1','8.8.4.4','8.26.56.26','208.67.222.222'],
                      action="callback",
                      callback=parse_resolvers,
                      type="string")
    parser.add_option("-F", "--force-scan", 
                    dest="force",
                    help="Force a re-scan of all the domains, including the ones previously explored and stored in the DB",  
                    default=False, 
                    action="store_true")
    parser.add_option("-U", "--dont-update", 
                    dest="dont_update",
                    help="Don't scan to update the 'orphan' collection in the DB",  
                    default=False, 
                    action="store_true")
    parser.add_option("-t", "--threads", 
                    dest="threads",
                    help="Number of threads to resolve domain names (default: 5).",  
                    default=5)
    parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=False,
                  help="Be verbose")

    return parser.parse_args()

def is_ip(d):
    """Returns True when a string looks like an IP address. False otherwise."""
    return re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",d) is not None

def valid_fld(host: str):
    # Ignore the malformed sources that could be handlers like 'https:' or 'wss:' with a regexp
    handlerre=re.compile("^\w+(\.\w+)+$",flags=re.IGNORECASE) # re.compile("^\w+:$",flags=re.IGNORECASE)
    return (handlerre.match(host) is not None)

def get_allowed_domains(scans: list):
    """
    This method list all allowed domains in the CSP headers found for every scan of the database.
    Parameters
    ----------
    scans : list
        This is a list or scan documents stored in the database
    
    Returns
    -------
    list:
        Return a list of allowed domains present within the csp policies of all scans
    """
    allowed_domains=[]

    for scan in scans:
        # Scan the current csp policy
        if ("csp" in scan.keys() and scan["csp"] is not None):
            for k,v in scan["csp"].items():
                if ("-src" in k):
                    for value in v:
                        if (valid_fld(value)):
                            # This should be a URI, so we append it to the list
                            allowed_domains.append(value)
        # List also the domains of the cspro to be prepared before the target
        if ("cspro" in scan.keys() and scan["cspro"] is not None):
            for k,v in scan["cspro"].items():
                if ("-src" in k):
                    for value in v:
                        if (valid_fld(value)):
                            # This should be a URI, so we append it to the list
                            allowed_domains.append(value)
    return allowed_domains

def find_affected_directives(scan: dict,nxdomains: list, url: str):
    """This function find the CSP directive names that contain an orphan domain.
    Parameters
    ----------
    scan: dict
        This is a dict with the scan details pulled from the DB. It should caontain a csp policy to analyse.
    nxdomains: list
        This is a list with the domains that returned NXDOMAIN and are present somewhere in this csp
    Returns
    -------
    list
        An array of dictionaries containing the directive name and the domain that is present in this directive
    """
    csp=scan["csp"]
    cspro=scan["cspro"]
    affected = []

    if (csp is not None):
        for k,v in csp.items():
            for alowed_domain in v:
                # Transform the domain to fldn to match correctly
                ad_fld=extract(alowed_domain).domain+"."+extract(alowed_domain).suffix
                if (valid_fld(ad_fld)):
                    if (ad_fld in nxdomains):
                        nw={"header": "csp", "directive": k, "domain": ad_fld}
                        # Avoid duplicates
                        if nw not in affected:
                            affected.append(nw)
    
    if (cspro is not None):
        for k,v in cspro.items():
            for alowed_domain in v:
                # Transform the domain to fldn to match correctly
                ad_fld=extract(alowed_domain).domain+"."+extract(alowed_domain).suffix
                if (valid_fld(ad_fld)):
                    if (ad_fld in nxdomains):
                        nw={"header": "CSP-Report-Only", "directive": k, "domain": ad_fld}
                        # Avoid duplicates
                        if nw not in affected:
                            affected.append(nw)

    return affected

def find_nxdomains(allowed_domains,nxdoms):
    """This method intersect the members of two lists of domains.
    Parameters
    ----------
    allowed_domains: list
        This is a list containing the allowed domains in all CSP policies of the database.
        This list will be transformed to first level domains (fld) to be able to compare with the "nxdoms" parameter
    nxdoms: list
        This is a list containing all the potentially unregistered domains that returned NXDOMAIN 
    Returns
    -------
    list
        The intersection between these two lists
    """
    allowed_flds=list(set([extract(ad).domain+"."+extract(ad).suffix for ad in allowed_domains]))
    intersection = list(set(allowed_flds) & set(nxdoms))
    if len(intersection)>0:
        return intersection
    else:
        return None

def get_domain_status(fld: str,resolver: Resolver) -> str:
    """This method just resolves the domain"""
    status="unknown"
    try:
        # TODO: Try to resolve AAAA records if this one A fails
        records = resolver.resolve(fld,"A")
        status="exists"
    except NXDOMAIN as nxde:
        status=DomainStatus.NXDOMAIN
        try:
            r=whois(fld)
        except PywhoisError as e:
            status=DomainStatus.NOTREGISTERED
        except Exception as e:
            pass
    except NoAnswer as nae:
        status=DomainStatus.NOANSWER
    except NoNameservers as nne:
        status=DomainStatus.NONS
    except Exception as e:
        status=DomainStatus.OTHER
    
    return status

def process_fld(fld: str, resolver: Resolver, force, thread_results):
    """This method contains the logic to pull domains from the DB and insert them back with their current status.
    It also controls whether a domain is well formed or not, in order to resolve or discard it."""
    # Retrieve the Orphan record from the DB if it exists
    explored_domain=Orphan.objects(fld=fld)
    # collection.find_one({"_id": fld})
    # First level domains that are not just alphanumeric
    status=DomainStatus.UNKNOWN
    if (force):
        logging.debug("First level domain %s forced check." % fld)
        status=get_domain_status(fld,resolver)
        
        # Update the entry in the DB
        orphan=Orphan(fld=fld,status=status,origin=OrphanOrigin.CSPDIRECTIVE)
        # result={"_id": fld, "status": status, "origin": "directive-sources", "date": datetime.now(tz=timezone.utc)}        
        if (explored_domain is None or len(explored_domain)==0):
            thread_results["new"].append(orphan)
        else:
            thread_results["update"].append(orphan)
    else:
        # Check if it hasn't been explored before
        if ((explored_domain is None or len(explored_domain)==0) and (valid_fld(fld))):
            logging.debug("First level domain %s not previously explored. Checking it." % fld)
            ##################
            # TODO: For the ones that ar valid, check if they are a variation of a legitimate well-known domains to flag a potential typosquatted domain
            ##################
            status=get_domain_status(fld,resolver)
            # Update the entry in the DB
            orphan=Orphan(fld=fld,status=status,origin=OrphanOrigin.CSPDIRECTIVE)
            # result={"_id": fld, "status": status, "origin": "directive-sources", "date": datetime.now(tz=timezone.utc)}
            thread_results["new"].append(orphan)
        else:
            logging.debug("First level domain %s is invalid or already explored. Skipping." % fld)


def update_orphan_domains(resolvers: list, nthreads: int, force: bool, allowed_flds):
    """This method update the 'orphan' collection with the status of the domains allowed in all the CSP directives of the 'header_scans' collection"""
    resolver = Resolver()
    # rlist = [res.strip() for res in options.resolvers.split(",")]
    resolver.nameservers=resolvers 

    new_doms=0
    update_doms=0
    c_total_new=Counter()
    c_total_update=Counter()
    for offset in range(0,len(allowed_flds),nthreads):
        # create one thread per row 
        threads=[]
        thread_results={
            "new": [],
            "update": []
        }
        for domain in allowed_flds[offset:offset+nthreads]:
            parsedd=extract(domain)
            fld="%s.%s" % (parsedd.domain, parsedd.suffix)
            th = threading.Thread(target=process_fld,args=(fld, resolver, force,thread_results,))
            threads.append(th)
            th.start()
        
        # Wait for all the threads to finish
        for index, thread in enumerate(threads):
            thread.join()

        # Insert all the new statuses
        new_doms+=len(thread_results["new"])
        c_new_status=Counter(map(lambda x: x["status"],thread_results["new"]))
        c_total_new+=c_new_status
        if (len(thread_results["new"])>0):
            # Insert bulk with mongoengine
            Orphan.objects.insert(thread_results["new"])

        # Update already explored statuses
        c_update_status=Counter(map(lambda x: x["status"],thread_results["update"]))
        c_total_update+=c_update_status
        update_doms+=len(thread_results["update"])
        for upd_orphan in thread_results["update"]:
            upd_orphan.save()

    # Print summary 
    logging.info("Inserted %s new domains" % (new_doms))
    logging.info(" With statuses: %s" % (c_total_new))
    logging.info("Updated %s domains in the DB" % (update_doms))
    logging.info(" With statuses: %s" % (c_total_update))

def flag_orphan_domains_weakness(csp_allowed_doms: pd.Series, csp_data, config):
    """This method insert in the Site collection a weaknesses per each orphan domain detected in one CSP directive."""
    # Update the list of domains that we are going to use to search in our database
    # by joining the previously resolved domains with the information we already have in our database
    db_orphans=list(Orphan.objects(status=DomainStatus.NOTREGISTERED))
    db_nxd=list(map(lambda x: x.fld, db_orphans))
    # Now iterate through the Series of csp_allowed_doms to detect where the previous orphan domains appear
    # return the array of domains not registered. I find the hits by intersecting both arrays, the x and the nxdomains with the set() trick
    # If there's no intersection, return None
    flags_nxd=csp_allowed_doms.map(lambda x: find_nxdomains(x,db_nxd))
    csp_data["flags_nxd"]=flags_nxd

    # Now, push the vulnerability if it's not already there
    # Iterate throught all the csp rows that are not null in the column "flags_nxd" and push the vuln
    wname="ORPHANDOMAIN"
    csp_with_ndx=csp_data[csp_data["flags_nxd"].notnull()]
    for idx,row in csp_with_ndx.iterrows():
        # Check if the weakness already exists for this document in the DB
        odv=Site.objects(url=row["url"],final_url=row["final_url"],scans__weaknesses__ORPHANDOMAIN__exists=1)
        if (len(odv)==0):
            all_orphans={}
            scans_affected_directives=list(map(lambda scans: find_affected_directives(scans,csp_data["flags_nxd"].iloc[idx],row["url"]), row["scans"]))
            scan_number=0
            for affected_directives in scans_affected_directives:
                scan_weanesses=[]
                for afd in affected_directives:
                    weakness_desc=config["general"]["vulns_explanation"][wname].format(afd["domain"],afd["directive"],afd["header"])
                    # The weakness does not exists, push it to the array of weaknesses
                    scan_weanesses.append(weakness_desc)
                # Add the array containing all the weaknesses descriptions
                all_orphans[str(scan_number)]=scan_weanesses
                
                # Add all directives to the adequate scan element of the array of  scans
                if (len(all_orphans)>0):
                    s=Site.objects(url=row["url"],final_url=row["final_url"]).first()
                    s.scans[scan_number].weaknesses[wname]=all_orphans[str(scan_number)]
                    s.save() # The save will complain about the _id of the document
                
                # Increment the scan number where the results will be stored
                scan_number+=1
        else:
            logging.info("The vulnerability of %s has been previously inserted in the DB. Skipping." % row["_id"])


def main():
    (options,args)=parse_options()

    config = get_config(options.environment)
    connect_db(environment=options.environment)

    # Operate only with sites that have a csp field populated
    # filter = {"scans.csp": {'$nin': [ {}, None ] }}
    # n_documents = collection.count_documents(filter)
    sites_with_csp=Site.objects(scans__csp__nin=[{}, None])
    csp_data = pd.DataFrame(sites_with_csp._cursor) # headers_coll.find(filter))

    # Now list the sources from multiple *-src directives
    csp_allowed_doms=csp_data["scans"].map(get_allowed_domains)

    # Build the first level domain list
    unique_allowed_doms=set(csp_allowed_doms.explode().value_counts().keys())
    allowed_flds=list(set([extract(ad).domain+"."+extract(ad).suffix for ad in unique_allowed_doms]))
    
    # First update orphan domains collection
    if (not options.dont_update):
        update_orphan_domains(options.resolvers,options.threads,options.force,allowed_flds)

    # Now, flag the vulnerabilities in the Site collection
    flag_orphan_domains_weakness(csp_allowed_doms, csp_data, config)



if __name__ == "__main__":
    main()