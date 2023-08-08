#!/usr/bin/env python

# This script will explore the database and will flag the CSP vulnerabilities found on the sites
# As a result, we will update each site with a new field called "csp_vulnerabilities" that will contain each vuln detected
# The vulnscan be:
# 1. No CSP defined (score would weight the same as the sum of the rest of weaknesses defined here)
# 2. "unsafe-inline" found on the *-src
# 3. "unsafe-eval" found on the *-src
# 4. Lenient scheme defined on the policy (https: or http:, etc.)
# 5. It only has CSP-ReportOnly headers
# 6. Third-party subdomains trust can be abusedd to inject or extract data from the target site
# 7. Not defined default-src: There is no fallback policy in case of absent directives, such as and script-src, worker-src
# 8. Not defined frame-ancestors: This allows clickjacking
# 9. Not defined report-to: Info. It is good to send error reports somewhere and have them monitorised
# 10. Not defined base-uri: Medium. Without it, a <base> tag can be injected into the page and all relative paths will be based with this URL
# 11. Not defined upgrade-insecure-requests: This wouldn't upgrade http:// resources to https:// resources
# 12.1 Not defined neither "child-src" nor "default-src": This allows to create Workers with javascript inside
# 12.2 Not defined neither "connect-src" nor "default-src": This allows to fetch any resource to exfiltrate data using script interfaces, such as <a>, fetch, etc.
# 12.3 Not defined neither "*-src" nor "default-src"

# TODO: Score the weakness with something different than CVSS, as base metrix require knowing the xploitation and AV, etc. that cannot easily defined

import pandas as pd
from numpy import isin
from pymongo.cursor import Cursor
import re
import logging
from datetime import datetime
from enum import Enum
import json
from optparse import OptionParser
from dashboard.utils.utils import get_config,get_headers_collection

# Config logging
logging.basicConfig(filename=datetime.now().strftime('logs/vulnerabilities-%Y%m%d_%H:%M:%S.log'),
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


class CSPVuln(Enum):
    UNDEFINED=0
    NOCSP=1 # 
    UNSAFEINLINE=2
    UNSAFEEVAL=3
    LENIENTSCHEME=4
    CSPRO=5
    THIRDPARTYABUSE=6
    DEFAULTSRC=7
    FRAMEANCESTORS=8
    REPORTTO=9
    BASEURI=10
    UPGRIR=11
    NDSCRIPTSRC=111
    NDCONNECTSRC=112
    NDFRAMESRC=113
    NDCHILDSRC=114
    NDOBJECTSRC=115

    def __str__(self) -> str:
        return self.name

class CSPVulnerabilities():
    def __init__(self) -> None:
        self.vulnerabilities={}

    # TODO: This function returns a score normalized between 0 and 10
    # It will count the number of vulnerabilities and follow this formula to assign a risk score
    # Score = 12*NOCSP + 2*UNSAFEINLINE + 2*UNSAFEEVAL + 1*LS + 11*CSPRO + 6*TPA + 
    # TODO: Define a risk function that makes sense. In the meantime, use just the number of vulnerabilities sum()
    # def risk_score(self):
    #    return 10
    
    def add_vuln(self,vuln: str, config, additional_info=None):
        explanation=config["general"]["vulns_explanation"][vuln]
        # TODO: Fix the firebase.com domain search to firebaseapp.com. Currently is erroneous and do not show the real domains that could be impacted
        if (vuln in [str(CSPVuln.UNSAFEEVAL),str(CSPVuln.UNSAFEINLINE),str(CSPVuln.LENIENTSCHEME)]):
            explanation=config["general"]["vulns_explanation"][vuln].format(additional_info)
        elif (vuln == str(CSPVuln.THIRDPARTYABUSE)):
            explanation=config["general"]["vulns_explanation"][vuln].format(*additional_info)
        self.vulnerabilities[vuln]= explanation

    # This returns true if the arrary vulnerabilities contains the vulnerability indicated by csp_vuln 
    def has_vuln(self,csp_vuln: CSPVuln):
        return csp_vuln in self.vulnerabilities.keys()

    def __str__(self) -> str:
        return json.dumps(self.vulnerabilities) 


class VulnerabilityChecker():
    def __init__(self, chunksize=10000, environment="majestic") -> None:
        self.chunksize=chunksize
        self.config=get_config(environment=environment)
        self.collection=get_headers_collection(self.config)
        self.total_documents = self.collection.count_documents({})
        self.data=pd.DataFrame()
        self.vulnerabilities={}

    # This function will spot weaknesses in the CSP headers stored
    def spot_weaknessess(self):
        # Do the load in batches instead full 1 million
        filter = {} #"vulnerabilities": {"$exists": 0}}
        # n_documents = self.collection.count_documents(filter)
        cursor: Cursor = self.collection.find(filter,{'url':1,'_id':1,'headers': 1, "csp": 1})
        # logging.info("Pulling %s documents from the DB..." % n_documents)
        dataset=cursor # .sort("_id").limit(self.chunksize)
        
        # Find vulnerabilities in this chunk of data
        self.data = pd.DataFrame(list(dataset))
        # Fix the headers column 
        # Transform all values to lower for better search 
        # self.data["lowcase_headers"]=self.data["headers"].map(lambda x: self.array_to_dict(x,tolower=True))
        # Filter the results whose header field is not empty
        data_headers_df=self.data[self.data["headers"].notnull()]
        # New method, now that I have the headers field fixed
        self.data["lowcase_headers"]=data_headers_df["headers"].map(lambda x: dict((k.lower(), v.lower()) for k,v in x.items()))
        # Find the rows with csp header defined
        # self.data["csp"]=self.data["lowcase_headers"].map(self.parse_csp)
        # self.data["hsts"]=self.data["lowcase_headers"].map(self.parse_hsts)

        csp_data=self.data[self.data["csp"].notnull()]
        # Explore this subset of data
        # TODO: Make the filters case insensitive to match all cases
        logging.info("Starting the vulneraiblity finding process")
        # Vuln #1
        self.data[str(CSPVuln.NOCSP)]=self.data["csp"].isnull()
        # Vuln #2, #3, #4, and #6 - Unsafe inline, unsafe eval, lenient handlers, wildcard third-party domains
        self.data["vulns_2346"]=csp_data["csp"].map(self.find_vulns_2346)
        # Vuln #5 - Report Only 
        # 20230723: Fixed bug with case sensitiviness of Content-Security-Policy. It was flagging sites sites erroneously as only CSP-RO due to casing
        self.data[str(CSPVuln.CSPRO)]=data_headers_df["headers"].map(lambda x: ("content-security-policy-report-only" in x.keys() and not "content-security-policy" in x.keys()))
        # Vuln #7
        self.data[str(CSPVuln.DEFAULTSRC)]=csp_data["csp"].map(lambda x: "default-src" not in x.keys())
        # Vuln #8
        self.data[str(CSPVuln.FRAMEANCESTORS)]=csp_data["csp"].map(lambda x: "frame-ancestors" not in x.keys())
        # Vuln #9
        self.data[str(CSPVuln.REPORTTO)]=csp_data["csp"].map(lambda x: "report-to" not in x.keys())
        # Vuln #10
        # TODO: Base URI can be specified, but can be abused as well, imagine a wildcard domain as base uri.
        self.data[str(CSPVuln.BASEURI)]=csp_data["csp"].map(lambda x: "base-uri" not in x.keys())
        # Vuln #11
        self.data[str(CSPVuln.UPGRIR)]=csp_data["csp"].map(lambda x: "upgrade-insecure-requests" not in x.keys())
        # Vuln 12.X
        # For the subset that do not have "default-src" defined, check the other *-src directives that may allow for XSS
        no_defaultsrc_data=self.data[self.data[str(CSPVuln.DEFAULTSRC)]==True]
        self.data[str(CSPVuln.NDSCRIPTSRC)]=no_defaultsrc_data["csp"].map(lambda x: "script-src" not in x.keys())
        self.data[str(CSPVuln.NDCONNECTSRC)]=no_defaultsrc_data["csp"].map(lambda x: "connect-src" not in x.keys())
        self.data[str(CSPVuln.NDOBJECTSRC)]=no_defaultsrc_data["csp"].map(lambda x: "object-src" not in x.keys())
        self.data[str(CSPVuln.NDFRAMESRC)]=no_defaultsrc_data["csp"].map(lambda x: "frame-src" not in x.keys())
        self.data[str(CSPVuln.NDCHILDSRC)]=no_defaultsrc_data["csp"].map(lambda x: "child-src" not in x.keys())

        # Now, create the "vulnerabilities" object to insert into MongoDB
        logging.info("Starting to build vulnerability object")
        self.data["vulnerabilities"]=self.data.apply(self.build_vuln_object,axis=1)

        # Update data in mongodb
        updates = []
        n=0
        logging.info("Vulnerabilities have been calculated. Updating DB...")
        for id, row in self.data.iterrows():
            updates.append(self.collection.update_one({'_id': row.get('_id')}, {'$set': {'vulnerabilities': row.get('vulnerabilities')}}, upsert=True))
            n+=1
            if (n%1000==0):
                logging.debug("#%s: %s was updated with vulnerabilities" % (n,row["url"]))
        
        logging.info("Updated %s rows with 'vulnerability' information" % len(updates))
            

    # Function to create a new pandas serie combining all the vulnerabilities
    def build_vuln_object(self,vulns):
        vuln_heads=[str(CSPVuln.NOCSP),
                    "vuln_2346",
                    str(CSPVuln.CSPRO),
                    str(CSPVuln.DEFAULTSRC),
                    str(CSPVuln.FRAMEANCESTORS),
                    str(CSPVuln.REPORTTO),
                    str(CSPVuln.BASEURI),
                    str(CSPVuln.UPGRIR),
                    str(CSPVuln.NDSCRIPTSRC),
                    str(CSPVuln.NDCONNECTSRC),
                    str(CSPVuln.NDOBJECTSRC),
                    str(CSPVuln.NDFRAMESRC),
                    str(CSPVuln.NDCHILDSRC)]
        
        self.vulnerabilities=CSPVulnerabilities()
        for index_name in vulns.index:
            if (index_name in vuln_heads and vulns[index_name]==True):
                self.vulnerabilities.add_vuln(index_name,self.config)
            # This is a special case that contains 4 vulns detected in one field, so we have to unpack them here:
            if (index_name == "vulns_2346" and (vulns.notnull()[index_name])):
                if (len(vulns[index_name])>0):
                    # We have a dictionary in this field that contains a key per each vulnerable directive 
                    for vuln_directive,vuln_flags in vulns[index_name].items():
                        if (vuln_flags[str(CSPVuln.UNSAFEINLINE)]):
                            self.vulnerabilities.add_vuln(str(CSPVuln.UNSAFEINLINE),self.config,additional_info=vuln_directive)
                        if (vuln_flags[str(CSPVuln.UNSAFEEVAL)]):
                            self.vulnerabilities.add_vuln(str(CSPVuln.UNSAFEEVAL),self.config,additional_info=vuln_directive)
                        if (vuln_flags[str(CSPVuln.LENIENTSCHEME)]):
                            self.vulnerabilities.add_vuln(str(CSPVuln.LENIENTSCHEME),self.config,additional_info=vuln_directive)
                        if (vuln_flags[str(CSPVuln.THIRDPARTYABUSE)]):
                            self.vulnerabilities.add_vuln(str(CSPVuln.THIRDPARTYABUSE),self.config,additional_info=(vuln_directive,vuln_flags[str(CSPVuln.THIRDPARTYABUSE)]))
                
        return self.vulnerabilities.vulnerabilities

    # This function returns an array indicating if unsafe-inline, unsafe-eval and a lenient handler is found on the values of a csp directive
    # This function will return an array with wildcard domains allowed in the *-src directives that can be abused to exfiltrate data or inject code
    # Check if any of the abusable domains from the config is present in the policy
    def find_vulns_2346(self,csp):
        ui=False    # Unsafe inline
        ue=False    # Unsafe eval
        lh=False    # Lenient handlers
        ad=[]       # Abusable domains
        
        # Abusable domains can be used to exfiltrate even with style-src and font-src
        abusable_domains=[list(dom)[0] for dom in map(lambda x: x.keys(),self.config["general"]["abusable_domains"])]
        # Prepend schemas to the vulnerable domains (http:// and https://) listed in the config.yaml
        map(lambda x: "http://{}".format(x),abusable_domains)
        ad_http=list(map(lambda x: "http://{}".format(x),abusable_domains))
        ad_https=list(map(lambda x: "https://{}".format(x),abusable_domains))
        abusable_domains+=(ad_http+ad_https)
        
        ui_ue_prone_directives=["script-src","worker-src","default-src","script-src-attr","script-src-elem","connect-src","object-src","frame-src"]

        vulns={}
        for directive,values in csp.items():
            ui=ue=lh=False
            # Only a few directives are prone to be abused with these sources, so we limit the flagging to these
            if (directive in ui_ue_prone_directives):
                ui=("'unsafe-inline'" in (lv.lower() for lv in values) or "unsafe-inline" in (lv.lower() for lv in values))
                ue=("'unsafe-eval'" in (lv.lower() for lv in values) or "unsafe-eval" in (lv.lower() for lv in values))
                lh=("http:" in (lv.lower() for lv in values) or "https:" in (lv.lower() for lv in values))

            addf=pd.DataFrame(values) 
            addf=addf[isin(values,abusable_domains)]
            if not addf.empty:
                ad = list(set(addf[0]))
            
            # Create the object to describe the vulnerabilities found per directive
            if (ui != False or ue != False or lh != False or len(ad)>0):
                vulns[directive]={
                    str(CSPVuln.UNSAFEINLINE): ui,
                    str(CSPVuln.UNSAFEEVAL): ue,
                    str(CSPVuln.LENIENTSCHEME): lh,
                    str(CSPVuln.THIRDPARTYABUSE): ad
                }

        return vulns

       
    # This function will transform an array of dictionaries to a dictionary
    # It will be used to transform the ugly headers field pulled from mongodb of arrays 
    # The parameter lower indicates whether the element key names should be transformed to low case for easier search on later phases
    def array_to_dict(self, arr: list, tolower: bool = False):
        result_dict = {}
        for arr_element in arr:
            k = list(arr_element.keys())[0]
            v = list(arr_element.values())[0]
            if (tolower):
                k = k.lower()
                v = v.lower()
            result_dict[k]=v
        return result_dict

    def parse_csp(self,lowcase_headers):
        try:
            csp = lowcase_headers["content-security-policy"]
            parsed_csp={}
            directives=[directive.strip() for directive in csp.split(";")]
            for directive in directives:
                dsplit=re.split("\s+",directive)
                dir_name=dsplit[0]
                dir_values=dsplit[1:]
                parsed_csp[dir_name]=dir_values
            return parsed_csp
        except KeyError as e:
            return None
        
    # Parse HSTS header
    def parse_hsts(self,lowcase_headers):
        try:
            hsts = lowcase_headers["strict-transport-security"]
            hsts_parsed = {}
            directives=[directive.strip() for directive in hsts.split(';')]
            # There's a max-age directive here
            for directive in directives:
                if ("=" in directive):
                    ds=directive.split("=")
                    mak=ds[0].strip()
                    mav=ds[1].strip()
                    hsts_parsed[mak]=mav
                else:
                    hsts_parsed[directive]=True

            return hsts_parsed 
        except KeyError as e:
            return None
            
        return directives
    
if (__name__ == "__main__"):
    (options,args)=parse_options()
    vulnc = VulnerabilityChecker(environment=options.environment)
    vulnc.spot_weaknessess()