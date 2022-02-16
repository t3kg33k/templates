#!/usr/bin/python3

# This script repo is found at Adam's github: https://github.com/AdamFSU/Scripts

# Notes:
# 1. Required Python packages: python-nmap
#       To install run: python3 -m pip install python-nmap
# 2. the $PYTHONPATH environment variable must be set:
#       example: export PYTHONPATH=/usr/lib/python3/dist-packages/
#       For CentOS: export PYTHONPATH=/usr/local/lib/python3.6/site-packages/
# 3. This script also uses the mail utility for sending email alerts
#       For CentOS: install mailx
# 4. flatfile called master_mac.txt with listing of known MAC addresses on the LAN
# 5. the nmap utility
# 6. Same server running postfix

# *** NOTE: THIS SCRIPT MUST BE RUN AS ROOT ***

# python module imports
import re
import os
import shutil
import nmap
import sys
import subprocess
from datetime import datetime

# === 2/15/2022, simbleau ===
regex_mac_exclusions = []
# regex_mac_exclusions.append("00:00:5e:00:53:af")  -- A single MAC address
regex_mac_exclusions.append("^00:.*")        ##     -- All MACs starting with '00:'
# ===========================

# variable containing the filepath of the nmap scan results file
mac_list = os.environ['HOME'] + "/maclist.txt"

# variable containing the filepath of the approved mac addresses on the LAN file
masterfile = os.environ['HOME'] + "/master_mac.txt"

# If a file from previous nmap scans exists, create a backup of the file
if os.path.exists(mac_list):
    shutil.copyfile(mac_list, os.environ['HOME'] + '/maclist_' +
                    datetime.now().strftime("%Y_%m_%H:%M") + '.log.bk')

# Open a new file for the new nmap scan results
f = open(mac_list, "w+")

# Print to console this warning
print("Don't forget to update your network in the nmap scan of this script")

# This block of code will scan the network and extract the IP and MAC address
# Create port scanner object, nm
nm = nmap.PortScanner()
# Perform: nmap -oX - -n -sn 192.168.1.69/24
# *** NOTE: -sP has changed to -sn for newer versions of nmap! ***
nm.scan(hosts='192.168.15.0/24', arguments='-n -sn')
# Retrieve results for all hosts found
nm.all_hosts()
# For every host result, write their mac address and ip to the $mac_list file
for host in nm.all_hosts():
    # If 'mac' expression is found in results write results to file
    if 'mac' in nm[host]['addresses']:
        f.write(str(nm[host]['addresses']) + "\n")
    # If 'mac' expression isn't found in results print warning
    elif nm[host]['status']['reason'] != "localhost-response":
        print("MAC addresses not found in results, make sure you run this script as root!")

# Close file for editing
f.close()
# Open file for reading
f = open(mac_list, "r")
# Read each line of file and store it in a list
mac_addresses = f.read().splitlines()
# Close file for reading
f.close()
# Open masterfile for reading
if os.path.isfile(masterfile):
    f2 = open(masterfile, "r")
else:
    print("Could not find master_mac file! Verify file path is correct!")
    sys.exit()

# Read each line of file and store it in a list
master_mac_addresses = f2.read().splitlines()
# Close file for reading
f2.close()

# Create empty list of new devices found on network
new_devices = []

# For every list entry in the mac_addresses list
for i in mac_addresses:
    # Convert the list index from a string to a dictionary so we can parse out mac address for comparison
    dic = eval(i)
    # Compare mac address portion of dictionary to mac addresses in the master_mac_addresses file
    # If the scanned mac address is not in the master_mac_addresses file

    # === 2/15/2022, simbleau ===
    mac_addr = dic['mac']
    # Check if mac address is excluded by regex
    for pattern in regex_mac_exclusions:
        if re.match(pattern, mac_addr) is not None:
            continue  # Match found, skip to next MAC
    # Check if known MAC in master list
    if mac_addr not in master_mac_addresses:
        # Add scanned mac address to new devices list
        new_devices.append(dic)
    # ===========================

# If the new_devices list isn't empty
if len(new_devices) != 0:
    # output a warning to the console
    warning = "\nWARNING!! NEW DEVICE(S) ON THE LAN!! - UNKNOWN MAC ADDRESS(ES): " + str(
        new_devices) + "\n"
    print(warning)

    # Create email notification of the warning
    try:
        # subject of email
        subject = "WARNING, new device on LAN!"
        # content of email
        content = "New unknown device(s) on the LAN: " + str(new_devices)
        # shell process of sending email with mutt
        m1 = subprocess.Popen('echo "{content}" | mail -s "{subject}" your@email.com'.format(
            content=content, subject=subject), shell=True)
        # output whether email was successful in sending or not
        print(m1.communicate())

    # if sending of the email fails, this will output why
    except OSError as e:
        print("Error sending email: {0}".format(e))
    except subprocess.SubprocessError as se:
        print("Error sending email: {0}".format(se))
