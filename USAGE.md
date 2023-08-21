Usage
=====

# Prerequisites

## Libraries
For this program to work, you need to have pipenv installed.
Then, the libraries in Pipfile should be installed by issuing the following commands:
```
pipenv install
pipenv shell
```
## Database setup
The scrip assumes a MongoDB database is running somewhere. I've added a Docker Compose  file in mongodb/docker-compose.yml to ease the local setup, but you can run another MongoDB wherever you want.
If you decide to use the docker MongoDB instance, edit the file [mongodb/docker-compose.yml](mongodb/docker-compose.yml) and personalise the values of "<db user>", "<db pass>", "<express user>", and "<express pass>". Then, to run the server, execute the following commands:
```
cd mongodb
docker-compose up
```
This will create a MongoDB instance, expose the port 27017 only to the localhost. It will also expose a local MongoDB Express web application in the port 8081 of the localhost. This MongoDB will help you visualising the contents of your database.

Alternativelly, you can use other MongoDB instance as long as you modify the configuration file "config.yml". There you can specify a new MongoDB environment where to store the information. You will have to specify the following information within the node "db_environments":
```
<environment_name>:
    user: <username>
    password: <password>
    host: <host>
    port: <port>
    database: <db name>
    headers_coll: <collection name for storing the headers>
    orphans_coll: <collection name for storing the orphan domains>
```

# Usage

This section describes how to use this repository to retrieve the headers of multiple web sites, parse their CSP and detect potential weaknesses to exploit. 

There are two ways to use this repo. 
1. Using the wrapper script with name "dresscode.py". See ["Dresscode Execution"](USAGE.md#dresscode-execution).
2. Executing each script individually. See ["Individual Execution"](USAGE.md#individual-execution)

# Dresscode Execution

The script "dresscode.py" is a wrapper around other 4 scripts that should be executed in a very specific order to retrieve all the CSP data from the sites and tap into the information from a Dash dashboard. 

## Input file
To simplify its usage, there's only one required argument, the file containing the list of URLs or domains to retrieve the HTTP headers from. The file should contain two columns: Rank and Domain/URL.

* The "Rank" colum is an integer indicating the global rank this site has in Internet (This field is used for the operations with the database where the popularity of the sites is important to know). If you don't know the rank of a site, just create a fake "Rank" column with numbers greater than 9000000.
* The "Domain/URL" column should contain the domain that you want to extract the headers and CSP info from. It can be a domain, e.g. "google.com", or it can be an URL, e.g. "https://www.google.com". The proccess will be faster if you already provide the script with URLs (for example by using 'httpx' against a list of domains), as specifying a domain only would default to connect to that domain using "https", and maybe some of the domains won't be listening for HTTPS connections, but for HTTP instead. This would produce a delay in the processing of the sites due to the timeout of the connection.

## Environment

Optionally, there is an option for the database environment you want to use: -e/--environment.
This option tells the script what MongoDB database and collection to use for storing the data. The environment name should match the one created in the configuration file "config.yml".

## Execution Example
To execute the wrapper with the file "top1m.csv" and introduce the results in the environment "majestic", execute:
```
python ./dresscode.py -e majestic top1m.csv
```

The tool will leave multiple logs where you can follow the execution in real time on the folder "logs/". To see it's execution in real time execute the following command:
```
tail -f logs/*.log
```

# Individual Execution

This section explain the order in which to execute the scripts. The advantages of using this approach over the wrapper, is that you have more control over specific parameters of the scripts. For example, if you want to change the DNS resolvers used by the script "update_orphan_domains.py" by specifying the parameter "-r/--resolvers", or if you want to change the chunk size allocated to the assincronous library aiohttp in the script "async_poll_headers.py" by specifying the parameter "-c/--chunksize".

This is the order you need to execute the script:

1. Get the list of domains or URLs to retrieve the info
	1. The format should be .csv with the following columns: Rank, Domain
	2. Assume you save the file as "targets.csv"
2. Open the file "config.yml" and modify the "db_environments" section to fit your purposes:
	1. Create a new db environment section or modify the two existing ones by changing the name of the database and collection where to store your results. Have in mind you will have to refer to that environment name in the following scripts. I.e. if you create a new environment with name "mydbenvironment", the following script ./async_poll_headers.py will have to use the flag and value "-e mydbenvironment" to explicitly indicate you want to use that environment.
	2. Open an account in scrapeops.io if you want to use the random request headers functionality. Paste your scrapeops API key in the file "config.yml" in the field "general -> scrapeops"
3. To pull the headers of your target sites, execute async_poll_headers.py:
	```
	python ./async_poll_headers.py -f targets.csv -e mydbenvironment
	```
4. When the previous step has finished retrieving the headers of the sites, let's find the weaknesses with "flag_vulnerabilities.py":
	```
	python ./flag_vulnerabilities.py -e mydbenvironment
	```
5. Whe the previous script finished detecting weaknesses, let's find out if there are some orphan domains (NXDOMAIN) within the CSP policies that you can take advantage of:
	```
	python ./update_orphan_domains.py -e mydbenvironment
	```
6. Now, let's introduce in the DB a new vulnerability per each site that has a CSP featuring a domain that is not registered:
	```
	python ./flag_orphan_domains.py -e mydbenvironment
	```
7. The DB is now updated.
8. Initiate the Dash dashboard by executing:
	```
	cd dashboard
	python app.py
	``` 
9. Open the browser to http://localhost:8050/