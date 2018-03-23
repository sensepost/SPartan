SPartan
=======
by Keiran Dennie

Requirements
-------------
The requests_ntlm and beautifulsoup4 libraries are required. Use the following command to install these with pip:

pip install -r requirements.txt 

Overview
-------
SPartan is a Frontpage and Sharepoint fingerprinting and attack tool.
Features:
- Sharepoint and Frontpage fingerprinting
- Management of Friendly 404s
- Default Sharepoint and Frontpage file and folder enumeration
- Active Directory account enumeration
- Download interesting files and documents, including detection of uninterpreted ASP and ASPX
- Search for keywords in identified pages
- Saves state from previous scans
- Site crawling
- Accepts NTLM creds and session cookies for authenticated scans

Usage
-----

Some information needed for SPartan Usage:

 python SPartan.py -u http://127.0.0.1 -f -c 
 *Note: You need to add 'http(s)://' to the URL*

* -u: "host URL to scan including HTTP/HTTPS"
* -c: "crawl the site for links (CTRL-C to stop crawling)
* -f: "perform frontpage scans"
* -k: "scrape identified pages for keywords (works well with crawl)
* -s: "perform sharepoint scans"
* --sps: "discover sharepoint SOAP services"
* --users: List users using Search Principals"
* -r: "(COMING SOON)execute a specified Frontpage RPC query"
* -t: "set maximum amount of threads (10 default)"
* -p: "(COMING SOON)find putable directories")
* --cookie: "use a cookie for authenticated scans"
* -d: "download pdf, doc, docx, txt, config, xml, xls, xlsx, webpart, config, conf, stp, csv and asp/aspx(uninterpreted)"
* -l: "provide credentials for authentication to Sharepoint" e.g., domain\user:password
* -v: "Render verbose output. By default SPartan will only render found resources."
* -i: "Don't attempt to verify SSL


License
-------

SPartan by SensePost is licensed under a Creative Commons Attribution-ShareAlike 4.0 International License (http://creativecommons.org/licenses/by-sa/4.0/) Permissions beyond the scope of this license may be available at http://sensepost.com/contact us/.
