# ddr-ioc-checker

A utility that makes queries against Vercara UltraDDR using a customer account ID and gives some analysis.  It also seeds the domains/FQDNs into the Watch Engine so that they can be later qualified and blocked if they are new to UltraDDR.

This tool reads the following from a text file, one item per line:
1. Fully-Qualified Domain Names (FQDNs)(Queries for an A record, shows if we got the IP address of the "blocked" page.)
2. Domain names (Queries for an A record, shows if we got the IP address of the "blocked" page.)
3. HTTP/HTTPS URLs by removing everything except the FQDN/domain.  (Queries for an A record, shows if we got the IP address of the "blocked" page.)
4. The domain half of email addresses (Anything to the right of "@".  Queries for an A record, shows if we got the IP address of the "blocked" page.)
5. IPv4 addresses (Makes a PTR query, should be shown as "PTR" in results)
6. IPv6 addresses (Makes a PTR query, should be shown as "PTR" in results)

Most CTI sources (example: CISA Advisories) "defang" CTI IOC by replacing "." with "[.]" so we remove that when we process the list.  Others transform "HTTP" and "HTTPS" into "HXXP" and "HXXPS" and so we also translate that.

An example file with the "canary FQDNs" for each of the UltraDDR categories is in testdata/categories.txt.
An example file with errors is in testdata/testfile.txt.


We give the status of each IOC:
1. Blocked: Blocked by DDR
2. Not Blocked: Not blocked by DDR
3. NXDOMAIN: The domain no longer exists or the FQDN inside of it does not exist.
4. PTR: For IP addresses, we query for PTR but UltraDDR doesn't block like it does for the other IOCs.
5. Error: Anything not in the above list


### To Use:
1. `git clone`
2. `cd ddr-ioc-checker`
3. `python3 -m venv ./venv`
4. `source ./venv/bin/activate`
5. `pip3 install -r requirements.txt`
6. `cp config.py.example config.py`
7. `vi config.py`
6. `python3 ./ddr-ioc-checker.py --strict -i testfile.txt`
7. Optional: `./do.bulk.sh` to update findings for ./data/*.txt.

I have pre-seeded ./data/ with CISA and other advisories and tested them against an UltraDDR account.

```commandline
python3 ./ddr-ioc-checker.py --help 

  ___  ___  ___   ___ ___   ___  
 |   \|   \| _ \ |_ _/ _ \ / __| 
 | |) | |) |   /  | | (_) | (__  
 |___/|___/|_|_\ |___\___/ \___| 
   ___ _  _ ___ ___ _  _____ ___ 
  / __| || | __/ __| |/ / __| _ \
 | (__| __ | _| (__| ' <| _||   /
  \___|_||_|___\___|_|\_\___|_|_\

usage: ddr-ioc-checker.py [-h] [-i FILE] [--strict]

Send queries for CTI IOC to UltraDDR.

options:
  -h, --help            show this help message and exit
  -i FILE, --input FILE
                        Input file with one IOC per line.
  --strict              Do not run validation if there are bad lines.This
                        ignores comments.
  --serial              Process in serial instead of parallel. This helps in
                        troubleshooting but is slower.
```