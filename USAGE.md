Usage
=====

1. Navigate to the folder with the project and:
	```
	pipenv install
	pipenv shell
	```
2. Get the list of domains or URLs to retrieve the info
	1. The format should be .csv with the following columns: Rank, Domain
	2. Assume you save the file as "targets.csv"
3. Open the file "config.yml" and modify the "db_environments" section to fit your purposes:
	1. Create a new db environment section or modify the two existing ones by changing the name of the database and collection where to store your results. Have in mind you will have to refer to that environment name in the following scripts. I.e. if you create a new environment with name "mydbenvironment", the following script ./async_poll_headers.py will have to use the flag and value "-e mydbenvironment" to explicitly indicate you want to use that environment.
	2. Open an account in scrapeops.io if you want to use the random request headers functionality. Paste your scrapeops API key in the file "config.yml" in the field "general -> scrapeops"
4. To pull the headers of your target sites, execute async_poll_headers.py:
	```./async_poll_headers.py -f targets.csv -e mydbenvironment```
5. When the previous step has finished retrieving the headers of the sites, let's find the weaknesses with "flag_vulnerabilities.py":
	```./flag_vulnerabilities.py -e mydbenvironment```
6. Whe the previous script finished detecting weaknesses, let's find out if there are some orphan domains (NXDOMAIN) within the CSP policies that you can take advantage of:
	```./update_orphan_domains.py -e mydbenvironment```
7. Now, let's introduce in the DB a new vulnerability per each site that has a CSP featuring a domain that is not registered:
	```./flag_orphan_domains.py -e mydbenvironment```
8. The DB is now updated.
9. Initiate the Dash dashboard by executing:
	```
	cd dashboard
	python app.py
	``` 
10. Open the browser to http://localhost:8050/