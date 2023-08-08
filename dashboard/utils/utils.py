from pymongo import MongoClient
import yaml
import re
import pathlib

# This function will transform an array of dictionaries to a dictionary
# It will be used to transform the ugly headers field pulled from mongodb of arrays 
# The parameter lower indicates whether the element key names should be transformed to low case for easier search on later phases
def array_to_dict(arr: list, tolower: bool = False):
    result_dict = {}
    if (type(arr)==list):
        for arr_element in arr:
            k = list(arr_element.keys())[0]
            v = list(arr_element.values())[0]
            if (tolower):
                k = k.lower()
                v = v.lower()
            result_dict[k]=v
    elif(type(arr)==dict):
        result_dict=arr
        
    return result_dict

def parse_csp(headers,lower=True,ro=True):
    parsed_csp=None
    parsed_cspro=None

    def parse(header_name):
        parsed_target={}
        try:
            target=headers[header_name]
            # Split by directive and values and remove empty directives
            directives=[directive.strip() for directive in target.split(";")]
            if ("" in directives):
                directives.remove("")
            for directive in directives:
                dsplit=re.split("\s+",directive)
                dir_name=dsplit[0]
                dir_values=dsplit[1:]
                parsed_target[dir_name]=dir_values
            return parsed_target
        except KeyError as e:
            return None

    name = "Content-Security-Policy" 
    if (lower):
        name="content-security-policy"
    parsed_csp=parse(name)

    if (ro):
        name = "Content-Security-Policy-Report-Only" 
        if (lower):
            name="content-security-policy-report-only"
        parsed_cspro=parse(name)
    
    return parsed_csp,parsed_cspro

  
# Parse HSTS header
def parse_hsts(headers,lower=False):
    try:
        if (lower):
            hsts = headers["strict-transport-security"]
        else:
            hsts = headers["Strict-Transport-Security"]
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
        

def get_config(environment="majestic") :
    config=None
    with open("%s/../../config.yml" % pathlib.Path(__file__).parent.resolve(),"r") as cfgf:
        config=yaml.load(cfgf,Loader=yaml.FullLoader)
    db_environment_config=config["db_environments"][environment]
    config["db"]=db_environment_config
    config["general"]=config["general"]
    return config

def get_headers_collection(config):
    mongoclient = MongoClient("mongodb://{u}:{p}@{h}:{P}/".format(u=config["db"]["user"],p=config["db"]["password"],h=config["db"]["host"],P=config["db"]["port"]))
    db = mongoclient.get_database(config["db"]["database"])
    return db.get_collection(config["db"]["headers_coll"])

def get_orphans_collection(config):
    mongoclient = MongoClient("mongodb://{u}:{p}@{h}:{P}/".format(u=config["db"]["user"],p=config["db"]["password"],h=config["db"]["host"],P=config["db"]["port"]))
    db = mongoclient.get_database(config["db"]["database"])
    return db.get_collection(config["db"]["orphans_coll"])
