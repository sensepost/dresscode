from pymongo import MongoClient
import yaml
import pathlib
from mongoengine import connect

def get_config(environment="majestic_snapshots") :
    config=None
    with open("%s/../config.yml" % pathlib.Path(__file__).parent.resolve(),"r") as cfgf:
        config=yaml.load(cfgf,Loader=yaml.FullLoader)
    db_environment_config=config["db_environments"][environment]
    config["db"]=db_environment_config
    config["general"]=config["general"]
    return config

def connect_db(environment="majestic_snapshots"):
    config=get_config(environment=environment)
    connect(db=config["db"]["database"],
            username=config["db"]["user"],
            password=config["db"]["password"],
            host=config["db"]["host"],
            port=config["db"]["port"],
            authentication_source="admin")

def get_headers_collection(config):
    mongoclient = MongoClient("mongodb://{u}:{p}@{h}:{P}/".format(u=config["db"]["user"],p=config["db"]["password"],h=config["db"]["host"],P=config["db"]["port"]))
    db = mongoclient.get_database(config["db"]["database"])
    return db.get_collection(config["db"]["headers_coll"])

def get_orphans_collection(config):
    mongoclient = MongoClient("mongodb://{u}:{p}@{h}:{P}/".format(u=config["db"]["user"],p=config["db"]["password"],h=config["db"]["host"],P=config["db"]["port"]))
    db = mongoclient.get_database(config["db"]["database"])
    return db.get_collection(config["db"]["orphans_coll"])

def get_environments():
    config=None
    with open("%s/../config.yml" % pathlib.Path(__file__).parent.resolve(),"r") as cfgf:
        config=yaml.load(cfgf,Loader=yaml.FullLoader)
    return list(config["db_environments"].keys())