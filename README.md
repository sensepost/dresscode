Dress Code - CSP Headers Mass Scanner
=====================================

# Context

This repository is the outcome of my research on the current status of Content-Security-Policy (CSP). I have presented the conclussions in Defcon 31 Appsec Village (https://www.appsecvillage.com/events/dc-2023) and I will be presenting it as well in Sector 2023 (https://www.blackhat.com/sector/2023/). 

# Summary

This project helps you scan the web sites in Internet in an (hopefully) efficient manner and retrieve the headers of each site. The headers will then be parsed for their Content-Security-Policy (CSP) information. This data, together with the geolocation of the site (ccTLD, IP geolocation) will be stored in a MongoDB database. 

To explore the information and reach conclusions about it you will be using the dashboard I created using Dash and Plotly Express. It will show you the information in an understandable manner with charts and all that colouful world.

You can use this project to see with what is the current health status of CSP accross the Top 1 million sites. For my research I used these two lists:
1. Majestic Million: https://majestic.com/reports/majestic-million
2. Cisco Umbrella Top 1M.

As long as the input file contains two columns with "Rank" and "Domain/URL", you can use other file sources, such as your own client domain list or the ol' Alexa top 1 million (http://s3.amazonaws.com/alexa-static/top-1m.csv.zip).

# Disclaimer

A large number of sites have to be scanned for the dashboard to work properly, currently, the Dash code has not been optimised to cater with exceptions produced by an insufficient number of data to populate some datasets. E.g. if you scan 100 sites and none of them have CSP data defined, some parts of the dashboard will not be drawn due to exceptions produced during MongoDB queries or Pandas filtering operations. 

I intend to fix this in future releases of the tool and present empty charts or a message indicating the lack of sufficient data to parse. But for now, an exception will occur. 

# Usage

To use the tool, refer to the [USAGE.md](USAGE.md) file.

# Future work

I would like to:
* Improve the code and refactoring the individual script to classes. I.e. tying up the house.
* Include other security headers in the analysis (e.g. HSTS)
* Execute the poll every few months to see the evolution of the security status.
* Increase the number of sites to scan

# Feedback

PRs are welcome.
Please, let me know of any other ideas or suggestions via twitter @felmoltor.