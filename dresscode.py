from optparse import OptionParser
import os
from dashboard.utils.utils import get_environments,get_config
import subprocess
from pymongo import MongoClient

# This script is a wrapper around the following separate scripts:
# 1. async_poll_headers.py
# 2. flag_vulnerabilities.py
# 3. update_orphan_domains.py
# 4. flag_orphan_domains.py
# 5. Boot up the Dashboard in http://localhost:8050 by executing "python dashboard/app.py"
# If you need to control other parameters, execute each of these scripts manually in this same sequence

def parse_options():
    envs=get_environments()

    parser = OptionParser(usage=f"{os.path.basename(__file__)} [options] <inputfile>")
    parser.add_option("-e", "--environment", dest="environment",
                  help=f"Environment name (default: {envs[0]})", 
                  type="choice", 
                  choices=envs, 
                  default=envs[0])

    (options,args)=parser.parse_args()
    if (len(args)==0):
        parser.error("Required positional argument <inputfile> was not found.")
        parser.print_help()
    else:
        if (os.path.exists(args[0])):
            options.file=args[0]
        else:
            parser.error("File indicated in <inputfile> argument was not found.")
            parser.print_help()
    
    return options

# This scripts checks the db access is rigth by connecting to the DB and listing the databases
def check_dbaccess(env):
    config=get_config(env)
    try:
        mongoclient = MongoClient("mongodb://{u}:{p}@{h}:{P}/".format(u=config["db"]["user"],p=config["db"]["password"],h=config["db"]["host"],P=config["db"]["port"]))
        mongoclient.list_database_names()
        return True
    except Exception as e:
        return False


######## 
# main #
########

if __name__ == '__main__':
    # Read options and make them available to all functions
    options=parse_options()

    # Ensure there's a mongodb running for the selected environment
    if (check_dbaccess(options.environment)):
        # Execute the stream 
        print(f"1. Executing dresscode against the sites of file {options.file}")
        subprocess.run(["python","async_poll_headers.py","-f",options.file,"-e",options.environment])
        print(" Scanning has finished.")
        
        print("2. Detecting weaknesses - General")
        subprocess.run(["python","flag_vulnerabilities.py","-e",options.environment])
        print(" Weaknesses detection has finished.")
        
        print("3. Updating orphan domains collection and detecting weaknesses - Orphan domains")
        subprocess.run(["python","flag_orphan_domains.py","-e",options.environment])
        print(" Detecting orphan domains in the database has finished.")
        
        print("4. Launching the dashboard")
        subprocess.Popen(cwd="dashboard/",args=["python","app.py"])
        print(" Dashboard launched, go to http://localhost:8050/ to see the result.")
    else:
        print(f"Error. MongoDB cannot accessed with the configuration specified in '{options.environment}' environment")
