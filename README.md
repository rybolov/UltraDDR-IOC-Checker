# ultraddr-ioc-checker

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
1. Blocked: Blocked by UltraDDR.
2. Allowed: Permitted by UltraDDR.
3. NXDOMAIN: The domain no longer exists or the FQDN inside of it does not exist.
4. PTR: For IP addresses, we query for PTR but UltraDDR doesn't block like it does for the other IOCs.
5. Error: Anything not in the above list.

### To Use:
1. `git clone`
2. `cd Ultraddr-IOC-Checker`
3. `python3 -m venv ./venv`
4. `source ./venv/bin/activate`
5. `pip3 install -r requirements.txt`
6. `cp config.py.example config.py`
7. `vi config.py` See *To Configure* below.
6. `python3 ./ultraddr-ioc-checker.py --strict -i testfile.txt`
7. Optional: `./do.bulk.sh` to update findings for ./data/*.txt.

I have pre-seeded ./data/ with CISA and other advisories and tested them against an UltraDDR account.

```commandline
python3 ./ultraddr-ioc-checker.py --help 
 

  _   _ _ _            ___  ___  ___  
 | | | | | |_ _ _ __ _|   \|   \| _ \ 
 | |_| | |  _| '_/ _` | |) | |) |   / 
  \___/|_|\__|_| \__,_|___/|___/|_|_\ 
 |_ _/ _ \ / __|                      
  | | (_) | (__                       
 |___\___/ \___|   _                  
  / __| |_  ___ __| |_____ _ _        
 | (__| ' \/ -_) _| / / -_) '_|       
  \___|_||_\___\__|_\_\___|_|         

usage: ultraddr-ioc-checker.py [-h] [-i FILE] [--strict] [--serial]
                               [--addpause] [-t THREADS] [--random RANDOM]
                               [--device DEVICE] [--once] [--verbose]

Send queries for CTI IOC to UltraDDR.

options:
  -h, --help            show this help message and exit
  -i FILE, --input FILE
                        Input file with one IOC per line.
  --strict              Do not run validation if there are bad lines.This
                        ignores comments.
  --serial              Process in serial instead of parallel. This helps in
                        troubleshooting but is slower.
  --addpause            Spread out the queries by waiting 3 seconds between.
  -t THREADS, --threads THREADS, --processes THREADS
                        Set the number of concurrent DoH query threads.
  --random RANDOM, -r RANDOM
                        Pick X random samples from the IoC list and query for
                        them.
  --device DEVICE, -d DEVICE
                        Send this name as the DeviceID. Default is 'DDR-IOC-
                        Checker' and can be configured in config.py
  --once                Only run the IOC list once. This is good for quickly testing
                        IOCs against categories, block/allow lists, and policy rules.
  --verbose             Display more detail on processing of IOC list.
```

### To Configure:

The config.py file supports the following configurations:

1. `ProviderURL` (required) is the URL the IOC Checker uses to make DoH queries to UltraDDR. 
2. `ClientID` (required) associates the DNS queries made by the tool with your UltraDDR account.
3. `BlockIP` (required) is the sinkhole IP address returned by UltraDDR and is used by the tool to determine if an FQDN was blocked.
4. `DeviceID` (optional) helps you identify the queries made by the IOC Checker tool when reviewing logs in UltraDDR.
