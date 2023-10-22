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

# TODO: To speedu up the process, add an option to only flag the vulnerabilities of the most recent scan
def parse_options():
    parser = OptionParser()
    parser.add_option("-e", "--environment", dest="environment",
                  help="Database Environment",  default="majestic")
    parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=False,
                  help="Be verbose")

    return parser.parse_args()

###############
# WeaknesEnum #
###############

class WeaknessEnum(Enum):
    UNDEFINED=0
    NOCSP=1 
    UNSAFEINLINE=2
    UNSAFEEVAL=3
    LENIENTSCHEME=4
    CSPRO=5
    THIRDPARTYABUSE=6
    NODEFAULTSRC=7
    NOFRAMEANCESTORS=8
    NOREPORTTO=9
    NOBASEURI=10
    NOUPGRIR=11
    NOSCRIPTSRC=111
    NOCONNECTSRC=112
    NOFRAMESRC=113
    NOCHILDSRC=114
    NOOBJECTSRC=115

    def __str__(self) -> str:
        return self.name
    

##############
# CSPWeaknes #
##############

class CSPWeakness():
    def __init__(self,name="",value=WeaknessEnum.UNDEFINED,explanation="") -> None:
        self.name=name
        self.value=value
        self.explanation=explanation
    
    def __str__(self) -> str:
        return "{}: {}".format(self.name, self.explanation)

#################
# CSPWeaknesses #
#################

# This class represents a collection of weaknesses
class CSPWeaknesses():
    def __init__(self) -> None:
        self.weaknesses=[] # This is an array of CSPWeakness objects

    # TODO: Remove the need of providing a "config" and an "additional_info" during vuln array construction
    def add_weakness(self,weakness: WeaknessEnum, config, additional_info=None):
        explanation=config["general"]["vulns_explanation"][str(weakness)]
        # TODO: Fix the firebase.com domain search to firebaseapp.com. Currently is erroneous and do not show the real domains that could be impacted
        if (weakness in [WeaknessEnum.UNSAFEEVAL,WeaknessEnum.UNSAFEINLINE,WeaknessEnum.LENIENTSCHEME]):
            explanation=config["general"]["vulns_explanation"][str(weakness)].format(additional_info)
        elif (weakness == WeaknessEnum.THIRDPARTYABUSE):
            explanation=config["general"]["vulns_explanation"][str(weakness)].format(*additional_info)
        
        # Now append the weakness to the array
        w = CSPWeakness(name=str(weakness),value=weakness,explanation=explanation)
        self.weaknesses.append(w)

    # This returns true if the arrary vulnerabilities contains the vulnerability indicated by csp_vuln 
    def has_vuln(self,weakness: WeaknessEnum):
        return weakness in list(map(lambda x: x.value,self.weaknesses))

    def __str__(self) -> str:
        return json.dumps(self.weaknesses) 

##############
# CSPChecker #
##############

# This class gets a string containing a CSP and will list the weaknesses
class CSPChecker():
    def __init__(self,config,csp=None) -> None:
        self.weaknesses=CSPWeaknesses()
        self.csp=csp
        self.config=config
        self.populate_abusable_domains()

    # This function populates the abusable domains array with http and https prefixes
    def populate_abusable_domains(self):
        self.abusable_domains=[list(dom)[0] for dom in map(lambda x: x.keys(),self.config["general"]["abusable_domains"])]
        # Abusable domains can be used to exfiltrate even with style-src and font-src
        # Prepend schemas to the vulnerable domains (http:// and https://) listed in the config.yaml
        map(lambda x: "http://{}".format(x),self.abusable_domains)
        ad_http=list(map(lambda x: "http://{}".format(x),self.abusable_domains))
        ad_https=list(map(lambda x: "https://{}".format(x),self.abusable_domains))
        self.abusable_domains+=(ad_http+ad_https)
        
        return len(self.abusable_domains)

    def find_weaknesses_2346(self,csp: dict, weaknesses: CSPWeaknesses) -> CSPWeaknesses:
        """
        This function spots the following weaknesses:
        * Weakness #2 - unsafe-inline present
        * Weakness #3 - unsafe-eval present
        * Weakness #4 - Lenient scheme (http:// https://) present
        * Weakness #6 - Abusable third-party domains
        
        These weaknesses require additional info, such as the directive name affected by the weakness or the domains that can be abused.
        Parameters
        ----------
        csp : dict
            The csp dictionary object to analyse in search of these weaknesses. 
        weaknesses : CSPWeaknesses
            The CSPWeaknesses object to be modified by this function. It will contain the new weaknesses, should they be detected.
        
        Returns
        -------
        CSPWeaknesses
            The object "weaknesses" modified with the new weaknesses detected
        """
        ad=[]       # Abusable domains
        ui_ue_prone_directives=["script-src","worker-src","default-src","script-src-attr","script-src-elem","connect-src","object-src","frame-src"]

        # Detect weakness #2, #3, and #4
        for directive_name,directive_values in csp.items():
            # Only a few directives are prone to be abused with these sources, so we limit the flagging to these
            if (directive_name in ui_ue_prone_directives):
                if ("'unsafe-inline'" in (lv.lower() for lv in directive_values) or "unsafe-inline" in (lv.lower() for lv in directive_values)):
                    # Add unsafe inline weakness
                    weaknesses.add_weakness(weakness=WeaknessEnum.UNSAFEINLINE,config=self.config,additional_info=directive_name)
                if ("'unsafe-eval'" in (lv.lower() for lv in directive_values) or "unsafe-eval" in (lv.lower() for lv in directive_values)):
                    # Add unsafe eval weakness
                    weaknesses.add_weakness(weakness=WeaknessEnum.UNSAFEEVAL,config=self.config,additional_info=directive_name)
                if ("http:" in (lv.lower() for lv in directive_values) or "https:" in (lv.lower() for lv in directive_values)):
                    # Add lenient scheme weakness
                    weaknesses.add_weakness(weakness=WeaknessEnum.LENIENTSCHEME,config=self.config,additional_info=directive_name)

            # Detect weakness #6
            directive_values_df=pd.DataFrame(directive_values) 
            directive_values_df=directive_values_df[isin(directive_values,self.abusable_domains)]
            if not directive_values_df.empty:
                ad = list(set(directive_values_df[0]))
                # Add the vulnerability to the object
                # Pass a tuple containing the directive_name where this was found and the list of abusable domains in it
                weaknesses.add_weakness(weakness=WeaknessEnum.THIRDPARTYABUSE,config=self.config,additional_info=(directive_name,ad))

        return weaknesses

    # This methods get a csp and return an object of class CSPVulnerabilities
    def get_weaknesses(self, csp: dict = None) -> CSPWeaknesses:
        # This will find the weaknesses of the policies 
        if csp is not None:
            self.csp=csp
            # List weaknesses
            # Vuln #1 - Already handled outside this function. Which is the lack of CSP headers defined
            # pass
            # Vuln #2, #3, #4, and #6 - Unsafe inline, unsafe eval, lenient handlers, wildcard third-party domains
            self.weaknesses=self.find_weaknesses_2346(csp,self.weaknesses)
            # Vuln #7
            if "default-src" not in csp.keys():
                self.weaknesses.add_weakness(WeaknessEnum.NODEFAULTSRC,config=self.config) 
            # Vuln #8
            if "frame-ancestors" not in csp.keys():
                self.weaknesses.add_weakness(WeaknessEnum.NOFRAMEANCESTORS,config=self.config) 
            # Vuln #9 and 9.1 (Lack of report-to and report-uri)
            if "report-to" not in csp.keys() and "report-uri" not in csp.keys():
                self.weaknesses.add_weakness(WeaknessEnum.NOREPORTTO,config=self.config) 
            # Vuln #10
            # TODO: Base URI can be specified, but can be abused as well, imagine a wildcard domain as base uri.
            if "base-uri" not in csp.keys():
                self.weaknesses.add_weakness(WeaknessEnum.NOBASEURI,config=self.config) 
            # Vuln #11
            if "upgrade-insecure-requests" not in csp.keys():
                self.weaknesses.add_weakness(WeaknessEnum.NOUPGRIR,config=self.config) 

            # Vuln 12.X
            if (self.weaknesses.has_vuln(WeaknessEnum.NODEFAULTSRC)):
                # Vuln #12.1
                if "script-src" not in csp.keys():
                    self.weaknesses.add_weakness(WeaknessEnum.NOSCRIPTSRC,config=self.config) 
                # Vuln #12.2
                if "connect-src" not in csp.keys():
                    self.weaknesses.add_weakness(WeaknessEnum.NOCONNECTSRC,config=self.config) 
                # Vuln #12.3
                if "object-src" not in csp.keys():
                    self.weaknesses.add_weakness(WeaknessEnum.NOOBJECTSRC,config=self.config) 
                # Vuln #12.4
                if "frame-src" not in csp.keys():
                    self.weaknesses.add_weakness(WeaknessEnum.NOFRAMESRC,config=self.config) 
                # Vuln #12.5
                if "child-src" not in csp.keys():
                    self.weaknesses.add_weakness(WeaknessEnum.NOCHILDSRC,config=self.config) 

        return self.weaknesses

#######################
# DBWeaknessPopulator #
#######################

# This class would get all the scans of the sites in the database and will pass their CSP to a CSPChecker instance
# The results of the weaknesses detection would be stored on the database
class DBWeaknessPopulator():
    def __init__(self, environment="majestic_snapshots") -> None:
        self.data = None
        self.config=get_config(environment=environment)
        self.collection=get_headers_collection(self.config)
    
    # Spot all vulnerabilities in each scan of the array
    def __spot_weaknesses(self,scans):
        scans_results=[]
        for scan in scans:
            cspc = CSPChecker(self.config)

            # Look for weaknesses in the scan if it does have headers collected but it does not have csp/cspro
            if scan["headers"] is not None and len(scan["headers"])>0:
                # No CSP header defined
                if (scan["csp"] is None or len(scan["csp"])==0):
                    # We only want to add one of these two NOCSP or CSPRO. Avoid count twice the same weakness
                    if (scan["cspro"] is None or len(scan["cspro"])==0):
                        # Vuln #1 - The scan does not have a CSP defined
                        cspc.weaknesses.add_weakness(WeaknessEnum.NOCSP,config=self.config)
                    else:
                        # The scan does not have a CSP defined but it has a CSPRO
                        # Vuln #5 - Report Only without CSP
                        cspc.weaknesses.add_weakness(WeaknessEnum.CSPRO,config=self.config)
                        # Analyse the csp-ro
                        cspc.get_weaknesses(csp=scan["cspro"])
                else:
                    # Analyse the csp
                    cspc.get_weaknesses(csp=scan["csp"])
                    if (scan["cspro"] is not None and len(scan["cspro"])>0):
                        # Analyse the csp-ro
                        cspc.get_weaknesses(csp=scan["cspro"])
            else:
                logging.debug("The scan does not have headers. Ignoring for weakness scan.")
                    
            # Add to the array of scan results the weaknesses detected
            # TODO: For now, we cannot differenciate whether this is a weakness of csp or cspro 
            scans_results.append(cspc.weaknesses)
        
        return scans_results

    def populate_database_weaknesses(self):
        # Get the data from the database that contains scans
        filter={"scans.headers": { '$exists': True, '$ne': {} }}
        
        # Retrieve all the sites and scans of each site
        cursor: Cursor = self.collection.find(filter,{'url':1,'_id':1,'scans': 1})
        
        # Find vulnerabilities in this chunk of data
        self.data = pd.DataFrame.from_records(cursor,index="_id")
        
        # get only those entries that have a "scans" array populated
        logging.debug("Reading data from database")
        with_scans_df=self.data[self.data["scans"].notnull()]

        # Now, for each scan of the site, we detect vulnerabilities
        logging.debug("Spotting weaknesses on the database")
        self.data["weaknesses"]=with_scans_df["scans"].map(lambda scans: self.__spot_weaknesses(scans))

        logging.debug("Finished listing the weaknesses")

        updates = []
        n=0
        logging.info("Vulnerabilities have been calculated. Updating DB...")
        for id, row in self.data.iterrows():
            # For each scan, we add the weaknesses to the field inside it
            scan_number=0
            for weakness_array in row.get('weaknesses'):
                # Tried to use jsonpickle to serialise vulnerabilities into a json that I could introduce in mongo, but it had a bug
                # so now, I have to build my own json object for the data I want so insert
                wea={}
                for welement in weakness_array.weaknesses:
                    wea[welement.name]=welement.explanation

                updates.append(self.collection.update_one({'_id': id}, {'$set': {"scans.%s.weaknesses" % scan_number: wea}}))
                scan_number+=1
            n+=1

            if (n%1000==0):
                logging.debug("#%s: %s was updated with vulnerabilities" % (n,id))
        
        logging.info("Updated %s rows with 'vulnerability' information" % len(updates))
        


#######################
# OLD IMPLEMENTATIONS #
#######################

# class VulnerabilityChecker():
#     def __init__(self, chunksize=10000, environment="majestic") -> None:
#         self.chunksize=chunksize
#         self.config=get_config(environment=environment)
#         self.collection=get_headers_collection(self.config)
#         self.total_documents = self.collection.count_documents({})
#         self.data=pd.DataFrame()
#         self.vulnerabilities={}

#     # This function will spot weaknesses in the CSP headers stored
#     def spot_weaknessess(self):
#         # Do the load in batches instead full 1 million
#         filter = {} #"vulnerabilities": {"$exists": 0}}
#         # n_documents = self.collection.count_documents(filter)
#         cursor: Cursor = self.collection.find(filter,{'url':1,'_id':1,'headers': 1, "csp": 1})
#         # logging.info("Pulling %s documents from the DB..." % n_documents)
#         dataset=cursor # .sort("_id").limit(self.chunksize)
        
#         # Find vulnerabilities in this chunk of data
#         self.data = pd.DataFrame(list(dataset))
#         # Fix the headers column 
#         # Transform all values to lower for better search 
#         # self.data["lowcase_headers"]=self.data["headers"].map(lambda x: self.array_to_dict(x,tolower=True))
#         # Filter the results whose header field is not empty
#         data_headers_df=self.data[self.data["headers"].notnull()]
#         # New method, now that I have the headers field fixed
#         self.data["lowcase_headers"]=data_headers_df["headers"].map(lambda x: dict((k.lower(), v.lower()) for k,v in x.items()))
#         # Find the rows with csp header defined
#         # self.data["csp"]=self.data["lowcase_headers"].map(self.parse_csp)
#         # self.data["hsts"]=self.data["lowcase_headers"].map(self.parse_hsts)

#         csp_data=self.data[self.data["csp"].notnull()]
#         # Explore this subset of data
#         # TODO: Make the filters case insensitive to match all cases
#         logging.info("Starting the vulneraiblity finding process")
#         # Vuln #1
#         # TODO: If the headers array is empty, do not flag this as a weakness. It was a problem retrieving the headers on my end
#         self.data[str(WeaknessEnum.NOCSP)]=self.data["csp"].isnull()
#         # Vuln #2, #3, #4, and #6 - Unsafe inline, unsafe eval, lenient handlers, wildcard third-party domains
#         self.data["vulns_2346"]=csp_data["csp"].map(self.find_vulns_2346)
#         # Vuln #5 - Report Only 
#         # 20230723: Fixed bug with case sensitiviness of Content-Security-Policy. It was flagging sites sites erroneously as only CSP-RO due to casing
#         self.data[str(WeaknessEnum.CSPRO)]=data_headers_df["headers"].map(lambda x: ("content-security-policy-report-only" in x.keys() and not "content-security-policy" in x.keys()))
#         # Vuln #7
#         self.data[str(WeaknessEnum.NODEFAULTSRC)]=csp_data["csp"].map(lambda x: "default-src" not in x.keys())
#         # Vuln #8
#         self.data[str(WeaknessEnum.NOFRAMEANCESTORS)]=csp_data["csp"].map(lambda x: "frame-ancestors" not in x.keys())
#         # Vuln #9
#         self.data[str(WeaknessEnum.NOREPORTTO)]=csp_data["csp"].map(lambda x: "report-to" not in x.keys())
#         # Vuln #10
#         # TODO: Base URI can be specified, but can be abused as well, imagine a wildcard domain as base uri.
#         self.data[str(WeaknessEnum.NOBASEURI)]=csp_data["csp"].map(lambda x: "base-uri" not in x.keys())
#         # Vuln #11
#         self.data[str(WeaknessEnum.NOUPGRIR)]=csp_data["csp"].map(lambda x: "upgrade-insecure-requests" not in x.keys())
#         # Vuln 12.X
#         # For the subset that do not have "default-src" defined, check the other *-src directives that may allow for XSS
#         no_defaultsrc_data=self.data[self.data[str(WeaknessEnum.NODEFAULTSRC)]==True]
#         self.data[str(WeaknessEnum.NOSCRIPTSRC)]=no_defaultsrc_data["csp"].map(lambda x: "script-src" not in x.keys())
#         self.data[str(WeaknessEnum.NOCONNECTSRC)]=no_defaultsrc_data["csp"].map(lambda x: "connect-src" not in x.keys())
#         self.data[str(WeaknessEnum.NOOBJECTSRC)]=no_defaultsrc_data["csp"].map(lambda x: "object-src" not in x.keys())
#         self.data[str(WeaknessEnum.NOFRAMESRC)]=no_defaultsrc_data["csp"].map(lambda x: "frame-src" not in x.keys())
#         self.data[str(WeaknessEnum.NOCHILDSRC)]=no_defaultsrc_data["csp"].map(lambda x: "child-src" not in x.keys())

#         # Now, create the "vulnerabilities" object to insert into MongoDB
#         logging.info("Starting to build vulnerability object")
#         self.data["vulnerabilities"]=self.data.apply(self.build_vuln_object,axis=1)

#         # Update data in mongodb
#         updates = []
#         n=0
#         logging.info("Vulnerabilities have been calculated. Updating DB...")
#         for id, row in self.data.iterrows():
#             updates.append(self.collection.update_one({'_id': row.get('_id')}, {'$set': {'vulnerabilities': row.get('vulnerabilities')}}, upsert=True))
#             n+=1
#             if (n%1000==0):
#                 logging.debug("#%s: %s was updated with vulnerabilities" % (n,row["url"]))
        
#         logging.info("Updated %s rows with 'vulnerability' information" % len(updates))
            

#     # Function to create a new pandas serie combining all the vulnerabilities
#     def build_vuln_object(self,vulns):
#         vuln_heads=[str(WeaknessEnum.NOCSP),
#                     "vuln_2346",
#                     str(WeaknessEnum.CSPRO),
#                     str(WeaknessEnum.NODEFAULTSRC),
#                     str(WeaknessEnum.NOFRAMEANCESTORS),
#                     str(WeaknessEnum.NOREPORTTO),
#                     str(WeaknessEnum.NOBASEURI),
#                     str(WeaknessEnum.NOUPGRIR),
#                     str(WeaknessEnum.NOSCRIPTSRC),
#                     str(WeaknessEnum.NOCONNECTSRC),
#                     str(WeaknessEnum.NOOBJECTSRC),
#                     str(WeaknessEnum.NOFRAMESRC),
#                     str(WeaknessEnum.NOCHILDSRC)]
        
#         self.vulnerabilities=CSPWeaknesses()
        
#         for index_name in vulns.index:
#             if (index_name in vuln_heads and vulns[index_name]==True):
#                 self.vulnerabilities.add_vuln(index_name,self.config)

#             # This is a special case that contains 4 vulns detected in one field, so we have to unpack them here:
#             if (index_name == "vulns_2346" and (vulns.notnull()[index_name])):
#                 if (len(vulns[index_name])>0):
#                     # We have a dictionary in this field that contains a key per each vulnerable directive 
#                     for vuln_directive,vuln_flags in vulns[index_name].items():
#                         if (vuln_flags[str(WeaknessEnum.UNSAFEINLINE)]):
#                             self.vulnerabilities.add_vuln(str(WeaknessEnum.UNSAFEINLINE),self.config,additional_info=vuln_directive)
#                         if (vuln_flags[str(WeaknessEnum.UNSAFEEVAL)]):
#                             self.vulnerabilities.add_vuln(str(WeaknessEnum.UNSAFEEVAL),self.config,additional_info=vuln_directive)
#                         if (vuln_flags[str(WeaknessEnum.LENIENTSCHEME)]):
#                             self.vulnerabilities.add_vuln(str(WeaknessEnum.LENIENTSCHEME),self.config,additional_info=vuln_directive)
#                         if (vuln_flags[str(WeaknessEnum.THIRDPARTYABUSE)]):
#                             self.vulnerabilities.add_vuln(str(WeaknessEnum.THIRDPARTYABUSE),self.config,additional_info=(vuln_directive,vuln_flags[str(WeaknessEnum.THIRDPARTYABUSE)]))
                
#         return self.vulnerabilities.weaknesses

#     # This function returns an array indicating if unsafe-inline, unsafe-eval and a lenient handler is found on the values of a csp directive
#     # This function will return an array with wildcard domains allowed in the *-src directives that can be abused to exfiltrate data or inject code
#     # Check if any of the abusable domains from the config is present in the policy
#     def find_vulns_2346(self,csp):
#         ui=False    # Unsafe inline
#         ue=False    # Unsafe eval
#         lh=False    # Lenient handlers
#         ad=[]       # Abusable domains
        
#         # Abusable domains can be used to exfiltrate even with style-src and font-src
#         abusable_domains=[list(dom)[0] for dom in map(lambda x: x.keys(),self.config["general"]["abusable_domains"])]
#         # Prepend schemas to the vulnerable domains (http:// and https://) listed in the config.yaml
#         map(lambda x: "http://{}".format(x),abusable_domains)
#         ad_http=list(map(lambda x: "http://{}".format(x),abusable_domains))
#         ad_https=list(map(lambda x: "https://{}".format(x),abusable_domains))
#         abusable_domains+=(ad_http+ad_https)
        
#         ui_ue_prone_directives=["script-src","worker-src","default-src","script-src-attr","script-src-elem","connect-src","object-src","frame-src"]

#         vulns={}
#         for directive,values in csp.items():
#             ui=ue=lh=False
#             # Only a few directives are prone to be abused with these sources, so we limit the flagging to these
#             if (directive in ui_ue_prone_directives):
#                 ui=("'unsafe-inline'" in (lv.lower() for lv in values) or "unsafe-inline" in (lv.lower() for lv in values))
#                 ue=("'unsafe-eval'" in (lv.lower() for lv in values) or "unsafe-eval" in (lv.lower() for lv in values))
#                 lh=("http:" in (lv.lower() for lv in values) or "https:" in (lv.lower() for lv in values))

#             addf=pd.DataFrame(values) 
#             addf=addf[isin(values,abusable_domains)]
#             if not addf.empty:
#                 ad = list(set(addf[0]))
            
#             # Create the object to describe the vulnerabilities found per directive
#             if (ui != False or ue != False or lh != False or len(ad)>0):
#                 vulns[directive]={
#                     str(WeaknessEnum.UNSAFEINLINE): ui,
#                     str(WeaknessEnum.UNSAFEEVAL): ue,
#                     str(WeaknessEnum.LENIENTSCHEME): lh,
#                     str(WeaknessEnum.THIRDPARTYABUSE): ad
#                 }

#         return vulns

       
#     # This function will transform an array of dictionaries to a dictionary
#     # It will be used to transform the ugly headers field pulled from mongodb of arrays 
#     # The parameter lower indicates whether the element key names should be transformed to low case for easier search on later phases
#     def array_to_dict(self, arr: list, tolower: bool = False):
#         result_dict = {}
#         for arr_element in arr:
#             k = list(arr_element.keys())[0]
#             v = list(arr_element.values())[0]
#             if (tolower):
#                 k = k.lower()
#                 v = v.lower()
#             result_dict[k]=v
#         return result_dict

#     def parse_csp(self,lowcase_headers):
#         try:
#             csp = lowcase_headers["content-security-policy"]
#             parsed_csp={}
#             directives=[directive.strip() for directive in csp.split(";")]
#             for directive in directives:
#                 dsplit=re.split("\s+",directive)
#                 dir_name=dsplit[0]
#                 dir_values=dsplit[1:]
#                 parsed_csp[dir_name]=dir_values
#             return parsed_csp
#         except KeyError as e:
#             return None
        
#     # Parse HSTS header
#     def parse_hsts(self,lowcase_headers):
#         try:
#             hsts = lowcase_headers["strict-transport-security"]
#             hsts_parsed = {}
#             directives=[directive.strip() for directive in hsts.split(';')]
#             # There's a max-age directive here
#             for directive in directives:
#                 if ("=" in directive):
#                     ds=directive.split("=")
#                     mak=ds[0].strip()
#                     mav=ds[1].strip()
#                     hsts_parsed[mak]=mav
#                 else:
#                     hsts_parsed[directive]=True

#             return hsts_parsed 
#         except KeyError as e:
#             return None
            
#         return directives
    
# if (__name__ == "__main__"):
#     (options,args)=parse_options()
#     vulnc = VulnerabilityChecker(environment=options.environment)
    # vulnc.spot_weaknessess()

if (__name__ == "__main__"):
    (options,args)=parse_options()
    logging.debug("Creating weakness populator object")
    dbwp = DBWeaknessPopulator(environment=options.environment)
    logging.debug("Populating the DB with the weaknesses")
    dbwp.populate_database_weaknesses()