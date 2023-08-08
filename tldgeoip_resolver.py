from dashboard.utils.utils import get_config,get_headers_collection
import geoip2.database
import numpy as np
import pandas as pd
import logging
from datetime import datetime
from geoip2.errors import AddressNotFoundError

logging.basicConfig(filename=datetime.now().strftime('logs/update-country-%Y%m%d_%H:%M:%S.log'),
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%Y%m%d_%H:%M:%S',
                    level=logging.DEBUG)

# config=get_config()
# collection=get_mongo_collection(config)

class TLDIPResolver():
    def __init__(self,environment,geoip_file="dashboard/data/GeoIP/GeoLite2-Country.mmdb") -> None:
        self.config=get_config(environment)
        self.collection=get_headers_collection(self.config)
        self.reader=geoip2.database.Reader(geoip_file)
        # Initialize the translation CSV files
        self.init_tld_to_continent_db()

    # This function returns the country ISO-3 code of an IP address
    def get_ip_country(self, ip):
        country=None
        # logging.debug("Searching IP %s country" % ip)
        try:
            response=self.reader.country(ip)
            try:
                country=response.country.iso_code
            except Exception as aex:
                try:
                    country=response.registered_country.iso_code
                except Exception as aex2:
                    logging.error("Can't find the country code of the IP %s: %s" % (ip,aex))
    
        except AddressNotFoundError as anfe:
            logging.error("Address %s not found in the geoIP database" % ip)
        
        return country

    def get_tld_country_continent(self,cctld):
        country_iso3=None
        if (cctld in list(self.tld_to_iso.index)):
            if (type(self.tld_to_iso.loc[cctld].ISO) == str):
                country_iso3=self.tld_to_iso.loc[cctld].ISO
            else:
                country_iso3=self.tld_to_iso.loc[cctld].ISO.unique()[0] # tld_to_country_iso_df[tld_to_country_iso_df["TLD"]==cctld].ISO.values[0]
        continent=None
        if (country_iso3 in list(self.country_iso_to_continent.index)):
            continent=self.country_iso_to_continent.loc[country_iso3].Continent #country_iso_to_continent[country_iso_to_continent["ISO-3"]==country_iso3].Continent.values[0]

        return country_iso3,continent

    # This function just returns the most common element of an array 
    def most_common(lst):
        return max(set(lst), key=lst.count)
    
    # This function initializes the translation info to pass from tld to country ISO-3 and to Continent name
    def init_tld_to_continent_db(self):
        self.tld_to_country_iso_df=pd.read_csv("dashboard/data/countries.tlds.csv")
        self.country_iso_to_continent=pd.read_csv("dashboard/data/countries.continents.csv")
        self.tld_to_iso=pd.DataFrame(index=list(self.tld_to_country_iso_df["TLD"]),data={"ISO": list(self.tld_to_country_iso_df["ISO"])})
        self.country_iso_to_continent=pd.DataFrame(index=list(self.country_iso_to_continent["ISO-3"]),data={"Continent": list(self.country_iso_to_continent["Continent"])})

    # This function just retunrs the country and countinent of the IP address
    def get_ip_country_continent(self,ip):
        country = self.get_ip_country(ip)
        if country is not None:
            country=country.lower()

        # Assign the country of the IP address:
        country_iso3=None
        if (country in list(self.tld_to_iso.index)):
            if (type(self.tld_to_iso.loc[country].ISO) == str):
                country_iso3=self.tld_to_iso.loc[country].ISO
            else:
                country_iso3=self.tld_to_iso.loc[country].ISO.unique()[0]
        continent=None
        if (country_iso3 in list(self.country_iso_to_continent.index)):
            continent=self.country_iso_to_continent.loc[country_iso3].Continent #country_iso_to_continent[country_iso_to_continent["ISO-3"]==country_iso3].Continent.values[0]
        
        return country_iso3, continent

    # This function goes directly to the database and creates or fix the field "country" and "continent" of all the documents that do not have these fields
    def update_database_addresses(self):
        # Read the DB
        cursor=self.collection.find({'IPv4': {"$exists": 0}, "country.iso_code": {'$exists': 0} },{"url":1,"IPv4":1}).sort("_id")
        dn=0
        for doc in cursor:
            url=doc["url"]
            # Get the ccTLD if it has
            cctld=url.split(".")[-1:].pop()
            # Read the countries to tlds csv mapping file

            if ("IPv4" not in doc.keys()):
                if cctld in list(self.tld_to_country_iso_df["TLD"]):
                    # Assign the country of the ccTLD:
                    country_iso3="Unknown"
                    if (cctld in list(self.tld_to_iso.index)):
                        if (type(self.tld_to_iso.loc[cctld].ISO) == str):
                            country_iso3=self.tld_to_iso.loc[cctld].ISO
                        else:
                            country_iso3=self.tld_to_iso.loc[cctld].ISO.unique()[0] # tld_to_country_iso_df[tld_to_country_iso_df["TLD"]==cctld].ISO.values[0]
                    continent="Unknown"
                    if (country_iso3 in list(self.country_iso_to_continent.index)):
                        continent=self.country_iso_to_continent.loc[country_iso3].Continent #country_iso_to_continent[country_iso_to_continent["ISO-3"]==country_iso3].Continent.values[0]
                    logging.debug("Updating country iso of %s (%s) to : %s" % (url,"ccTDL",country_iso3))
                    self.collection.update_one({"_id": doc["_id"]},{"$set": {"country": {"iso_code": country_iso3, "reason": "ccTLD"}, "continent": {"name": continent, "reason": "ccTLD"}}},upsert=False)
            else:
                ips=doc["IPv4"]
                # Assign the country if its IPs
                if ips is not None:
                    cc=[]
                    for ip in ips:
                        c = self.get_country(ip,self.reader)
                        if (c is not None):
                            logging.debug("Country of IP %s was found: %s" % (ip,c))
                            cc.append(c)
                    # Count the most repeated country in the results and assign it 
                    if (len(cc)>0):
                        country=self.most_common(cc).lower()
                        # Assign the country of the IP address:
                        country_iso3="Unknown"
                        if (country in list(self.tld_to_iso.index)):
                            if (type(self.tld_to_iso.loc[country].ISO) == str):
                                country_iso3=self.tld_to_iso.loc[country].ISO
                            else:
                                country_iso3=self.tld_to_iso.loc[country].ISO.unique()[0]
                        continent="Unknown"
                        if (country_iso3 in list(self.country_iso_to_continent.index)):
                            continent=self.country_iso_to_continent.loc[country_iso3].Continent #country_iso_to_continent[country_iso_to_continent["ISO-3"]==country_iso3].Continent.values[0]
                        logging.debug("Updating country iso of %s (%s) [%s] to : %s" % (url,ip,"IPv4",country_iso3))
                        self.collection.update_one({"_id": doc["_id"]},{"$set": {"country": {"iso_code": country_iso3, "reason": "IPv4"}, "continent": {"name": continent, "reason": "IPv4"}}},upsert=False)
                    else:
                        logging.debug("The country of IP %s could not be found" % ip)
            if (dn%1000==0):
                print("Document Number: %s\r" % dn) 

            dn+=1

if __name__ == "__main__":
    gir = TLDIPResolver("umbrella","dashboard/data/GeoIP/GeoLite2-Country.mmdb")
    logging.info("Starting to add IPv4 geo info to the database")
    gir.update_database_addresses()
    logging.info("Done")