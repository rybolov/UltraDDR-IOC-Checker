#!/bin/python3

import urllib3
import time
import datetime
import json
import argparse
import os
import re
from joblib import Parallel, delayed
import csv
import random


if not os.path.exists('config.py'):
    exit('Error, you haven\'t set up a configuration.\nPlease copy config.py.example to config.py and change the ClientID.')
else:
    import config
    config = config.Config()
    if config.ClientID == 'CHANGEME':
        exit('Error, you haven\'t set up a ClientID in config.py.\nPlease fix and re-run.')

generationdate = datetime.datetime.now().strftime("%Y.%m.%d %I:%M:%S %p")
today = datetime.datetime.now().strftime("%Y-%m-%d")


print('''
  _   _ _ _            ___  ___  ___  
 | | | | | |_ _ _ __ _|   \\|   \\| _ \\ 
 | |_| | |  _| '_/ _` | |) | |) |   / 
  \\___/|_|\\__|_| \\__,_|___/|___/|_|_\\ 
 |_ _/ _ \\ / __|                      
  | | (_) | (__                       
 |___\\___/ \\___|   _                  
  / __| |_  ___ __| |_____ _ _        
 | (__| ' \\/ -_) _| / / -_) '_|       
  \\___|_||_\\___\\__|_\\_\\___|_|         
''')

# ----------Begin Input Validation----------
def is_valid_file(parser, filename):
    if not os.path.exists(filename):
        parser.error("The file %s does not exist!" % filename)
        quit(666)
    else:
        return filename

parser = argparse.ArgumentParser(description='Send queries for CTI IOC to UltraDDR.')
parser.add_argument('-i', '--input', dest='filename', required=False, metavar='FILE',
                    help='Input file with one IOC per line.', type=lambda x: is_valid_file(parser, x))
parser.add_argument('--strict', action='store_true', help="Do not run validation if there are bad lines.\
This ignores comments.", default=False)
parser.add_argument('--serial', action='store_true', help='Process in serial instead of parallel. \
This helps in troubleshooting but is slower.', default=False)
parser.add_argument('--addpause', action='store_true', help="Spread out the queries by waiting 3 seconds between.",
                    default=False)
parser.add_argument('-t', '--threads', '--processes', dest='threads', type=int, help='Set the number of concurrent DoH query threads.',
                    default=5)
parser.add_argument('--random', '-r', dest='random', type=int, help='Pick X random samples from the IoC list and query for them.',
                    default=0)
parser.add_argument('--device', '-d', type=str, help='Send this name as the DeviceID.  Default is \
                    \'DDR-IOC-Checker\' and can be configured in config.py. Use \'random\' to use a random set of \
                    device names')
args = parser.parse_args()
# ----------End Input Validation----------


class IOCList:
    """The whole list!!!"""

    def __init__(self):
        self.IOCnames = {}
        self.filename = ''
        self.allvalid = True
        self.failedlines = []
        self.random = 0
        self.csv = \
        [
            ['Date Generated:  ' + generationdate],
            ['Questions, comments, or complaints: contact threat-intel@vercara.com'],
            [],
            ['Query Name', 'UltraDDR Status']
        ]

    def __repr__(self):
        """Return string representation of everything."""
        return json.dumps(self.__dict__, default=obj_dict, indent=4)

    def get_iocs_from_file(self):
        linenumber = 0
        if not self.filename:
            exit('Error, no filename was passed.\nPlease use the -i flag to specify a file.\nUse --help for more information.')
        else:
            print('Openening file:', self.filename)
            with open(self.filename) as f_open:
                lines = f_open.readlines()
            for line in lines:
                linenumber += 1
                print('')
                print('Line number:', linenumber)
                line = line.strip()  # Remove whitespace
                line = line.rstrip('.')  # For any lists that use DNS-style FQDNs that end with a dot.
                line = line.lower()  # Use all lower-case
                line = re.sub('\[\.\]', '.', line)  # Most CTI list domains as foo[.]com to keep you from clicking on them.
                line=re.sub('^h[tx]{2}ps*://','', line)  # Remove "http://", "https://" "hxxp://" and "hxxps://"
                line = re.sub('/.*$', '', line)  # Remove "/path/and/anything/else/here" and rely on regex being "greedy"
                print(line)
                if re.search('^#', line):
                    print('Line is a comment: ', line)
                elif re.search('^$', line):
                    print('Line is empty: ', line)
                elif re.search('\s', line): # Disqualify because of spaces
                    print('Line contains a space in the middle of it,', line)
                    self.allvalid = False
                    self.failedlines.append(line)
                elif re.search('^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', line):  # IPv4 address is allowed
                    print('Line is valid IPv4 address: ', line)
                    self.IOCnames[line] = IOCName(line)
                elif re.search('^([0-9a-fA-F]{0,8}:){7}[0-9a-fA-F]{0,8}$', line):  # IPv6 address is allowed
                    print('Line is valid IPv6: ', line)
                    self.IOCnames[line] = IOCName(line)
                elif re.search('^[a-z0-9\-\.]*$', line):  # Domain/FQDN allowable characters is allowed
                    print('Line is valid FQDN/domain: ', line)
                    self.IOCnames[line] = IOCName(line)
                elif re.search('^.+@[a-z0-9\-\.]*$', line): # Email address is allowed
                    print('Line is valid email: ', line)
                    self.IOCnames[line] = IOCName(line)
                else:
                    print('Line contains an invalid character: ', line)
                    self.allvalid = False
                    self.failedlines.append(line)
            if (not self.allvalid) and args.strict:
                print('')
                print('We have failed lines and are running in strict mode, so we will exit.')
                for line in self.failedlines:
                    print(line)
                quit()

    def makeCSV(self):
        for ioc in self.IOCnames.values():
            # print(ioc)
            self.csv.append([ioc.iocname, ioc.status])
            # print(ioc.status)

    def get_ddr_serial(self):
        for ioc in self.IOCnames.values():
            ioc.get_ddr()
            if args.addpause:
                time.sleep(3)
        time.sleep(10)
        # Second Run!
        for ioc in self.IOCnames.values():
            ioc.get_ddr()
            if args.addpause:
                time.sleep(3)

    def get_ddr_multiprocessing(self):
        Parallel(n_jobs=args.threads, require='sharedmem')(delayed(get_ddr_multiprocessing)(iocname)
                                                for iocname in self.IOCnames.values())
        time.sleep(10)
        # Second Run!
        Parallel(n_jobs=args.threads, require='sharedmem')(delayed(get_ddr_multiprocessing)(iocname)
                                                for iocname in self.IOCnames.values())

    def get_randoms(self):
        if self.random > 0:
            print('Using {} random entries'.format((self.random)))
            newIOCnames = {}
            IOCkeys = list(self.IOCnames.keys())
            # print(IOCkeys)
            randomIOCnames = random.choices(IOCkeys, k=self.random)
            for IOC in randomIOCnames:
                newIOCnames[IOC] = self.IOCnames[IOC]
            self.IOCnames = newIOCnames

class IOCName:
    """An individual FQDN, domain, or IP address"""

    def __init__(self, iocname):
        self.iocname = iocname
        self.status = ''
        self.rawresults = ''
        self.type = ''
        self.deviceid = config.DeviceID
        if args.device:
            self.deviceid = args.device

    def __repr__(self):
        """Return string representation of Finding."""
        return json.dumps(self.__dict__, default=obj_dict, indent=4)

    def get_ddr(self):
        for looper in range(3):
            try:
                http = urllib3.PoolManager()
                if re.search('@', self.iocname):
                    queryurl = config.ProviderURL + re.sub('^.*@', '', self.iocname) + '&type-'
                else:
                    queryurl = config.ProviderURL + self.iocname + '&type='
                if re.search('^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', self.iocname):  # IPv4 Address
                    queryurl += 'PTR'
                elif re.search('^([0-9a-fA-F]{0,8}:){7}[0-9a-fA-F]{0,8}$', self.iocname):  # IPv6 Address
                    queryurl += 'PTR'
                else:
                    queryurl += 'A'
                print(queryurl)
                if self.deviceid == 'random':
                    # print('Choosing random device name')
                    deviceid = random.choice(devicenames)
                    # print(deviceid)
                else:
                    deviceid = self.deviceid
                    print('device id', deviceid)

                req = http.request('GET', queryurl,
                                   headers={
                                            'Accept': 'application/dns-json',
                                            'X-UltraDDR-Client-id': config.ClientID,
                                            'X-UltraDDR-Device-Name': deviceid # deviceid
                                            }
                                   )
                ddr_results = json.loads(req.data.decode('utf-8'))
                break
            except urllib3.exceptions.NewConnectionError as e:
                print("New connection error. Resending....")
                time.sleep(looper * 2)
            except urllib3.exceptions.HTTPError as e:
                if re.search('certificate verify failed: unable to get local issuer certificate', e.reason):
                    print('Couldn\'t find the CA Certs, import ultraddr-ca-cert.pem and run '\
                          '\'<phythonhome/Install Certificates.command\'')
                print(e.reason)
                print("HTTP error. Resending....")
                time.sleep(looper * 2)
            except urllib3.exceptions.ConnectTimeoutError as e:
                print("Connection timed out. Resending....")
                time.sleep(looper * 2)
            except urllib3.exceptions.MaxRetryError as e:
                print("Connection timed out. Resending....")
                time.sleep(looper * 2)
            except:
                print("Connection error. Resending....")
                time.sleep(looper * 2)
        else:
            print("\n======Connection timed out.  Aborting....======\n")
        # print(json.dumps(ddr_results, indent=4))

        self.rawresults = json.dumps(ddr_results)
        if 'Answer' in ddr_results.keys():
            print(json.dumps(ddr_results['Answer'][0]['data'], indent=4))
            if ddr_results['Answer'][0]['data'] == '20.13.128.62':
                self.status = 'Blocked'
                print('Blocked')
            else:
                self.status = 'Not Blocked'
                print('Not Blocked')
            # print(self.status)
        else:
            self.status = "NXDOMAIN"
        # print(self)

def get_ddr_multiprocessing(ioc):
    ioc.get_ddr()
    if args.addpause:
        time.sleep(3)


def readfile(filename):
    pass


def get_machine_names(number):
    names = []
    characters = '1234567890abcdefghijklmnopqrstuvwxyz'
    types = ['ws', 'lnx', 'lap', 'w2k', 'mac']
    identifiers = []
    domain = random.choice(['.zone', '.domain', '.company'])
    tld = random.choice(['.local', '.internal', '.corp', '.private'])
    for i in range(number):
        name = random.choice(types) + '-'
        for y in range(8):
            name += str(random.choice(characters))
        name += domain + tld
        names.append(name)
    # print(names)
    return names


def obj_dict(obj):  # Needed for the json.dumps() call in the __repr__ of the classes.
    return obj.__dict__


def main():
    fullfile = IOCList()
    fullfile.filename = args.filename
    fullfile.get_iocs_from_file()
    fullfile.random = args.random
    fullfile.get_randoms()
    if args.serial:
        fullfile.get_ddr_serial()
    else:
        fullfile.get_ddr_multiprocessing()
    fullfile.makeCSV()
    # print(json.dumps(fullfile.csv, indent=4))
    # print(fullfile)
    cvsfilename = args.filename + '-' + today + '.csv'
    with open(cvsfilename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(fullfile.csv)


if args.device == 'random':
    print("Using random device names.")
    devicenames = get_machine_names(100)

if __name__ == "__main__":
    main()