# This script is provided as-is and was written for demonstration purposes.
# Replace all organization-specific paths and domains before use.
import time
import re
import os
import getpass
from datetime import datetime
import ipaddress  # For IP subnet exclusion

# Create Logs directory if it doesn't exist
if not os.path.exists('Logs'):
    os.makedirs('Logs')

## GLOBAL
FQDN_REGEX = re.compile(
    r'^(?=.{1,253}$)(?!.*[-.]{2})[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
)

## Function to log entries with timestamps
def log_entry(file_type, entry, username):
    log_filename = os.path.join('Logs', f'{file_type}_TimeLog.txt')
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_filename, 'a') as log_file:
        log_file.write(f'[{timestamp}] {entry} Made by: {username}\n')
def is_ip_in_exclusion_file(ip, excluded_file='excluded_ips.txt'):
    try:
        with open(excluded_file,'r') as f:
            for line in f:
                if ip == line.strip():
                    return True
    except FileNotFoundError:
        pass
    return False
    
def extract_ips(input_string):
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'  # Regex for IPv4 addresses
    raw_ips = re.findall(ip_pattern, input_string)  # Extract potential IPs
    return list(set(raw_ips))  # Remove duplicates from input

## VALIDATION FUNCTIONS
def Check_Octate(ip):
    try:
        ipaddress.IPv4Address(ip)
        return "IP"
    except:
        return "none"

def local_validation(Lstring):
    patterns = ["192.168", "172.30", "172.16", "10.0"]
    return not any(Lstring.startswith(pattern) for pattern in patterns)

# New function to exclude IPs based on a subnet using ipaddress module.
def is_excluded_ip(ip):
    """
    Checks if the given IP address is within the excluded subnet.
    In this example, the excluded subnet is set to ******,
    which covers IP addresses from **** to *****
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        excluded_net = ipaddress.ip_network("******")
        return ip_obj in excluded_net
    except ValueError:
        return False

def Check_Special(dog):
    special_chars = [':','/','-','=','{','}','[',']']
    for char in dog:
        if char in special_chars:
            print('Contains special characters')
            return False
    return True

def is_valid_fqdn(input_string):
    pattern = r'^(?=.{1,253}$)(([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})$'
    return bool(re.match(pattern, input_string))
    return bool(FQDN_REGEX.match(input_string))

def is_string_in_file(file, search_string):
    try:
        with open(file, 'r') as f:
            return any(search_string in line.strip().split() for line in f)
    except FileNotFoundError:
        return False

def get_valid_int_input(item):
    try:
        return int(item)
    except ValueError:
        return False

def check_emp_format(input_string):
    parts = input_string.split(".")
    if len(parts) != 2:
        print("\nUse format: First.Last")
        return False
    first, last = parts
    if not first.isalpha() or not last.isalpha():
        print("\nNames must be alphabetic")
        return False
    if len(first) < 2 or len(last) < 2:
        print("\nNames must be ≥2 characters")
        return False
    return True

## BANNER
print("\t\t\t\t\t" + r"""
                                                                   __    _                                   
                                                            _wr""        "-q__                             
                                                        _dP                 9m_     
                                                       _#P                     9#_                         
                                                      d#@                       9#m                        
                                                     d##                         ###                       
                                                    J###                         ###L                      
                                                    {###K                       J###K                      
                                                    ]####K      ___aaa___      J####F                      
                                                __gmM######_  w#P""   ""9#m  _d#####Mmw__                  
                                             _g##############mZ_         __g##############m_               
                                           _d####M@PPPP@@M#######Mmp gm#########@@PPP9@M####m_             
                                          a###""          ,Z"#####@" '######"\g          ""M##m            
                                         J#@"             0L  "*##     ##@"  J#              *#K           
                                         #"               `#    "_gmwgm_~    dF               `#_          
                                        7F                 "#_   ]#####F   _dK                 JE          
                                        ]                    *m__ ##### __g@"                   F          
                                                               "PJ#####LP"                                 
                                         `                       0######_                      '           
                                                               _0########_                                   
                                             .               _d#####^#####m__              ,              
                                              "*w_________am#####P"   ~9#####mw_________w*"                  
                                                  ""9@#####@M""           ""P@#####@M""                    
                                        `""")

print("""

____|             |            __ )  |            |   _)                 \          |                         |  _)             
 |    _ \  _ \  _` |  _ \  __|  __ \  |  _ \   __| |  / | __ \   _` |    _ \   |   | __|  _ \  __ `__ \   _` | __| |  _ \  __ \  
 __|  __/  __/ (   |  __/ |     |   | | (   | (      <  | |   | (   |   ___ \  |   | |   (   | |   |   | (   | |   | (   | |   | 
_|  \___|\___|\__,_|\___|_|    ____/ _|\___/ \___|_|\_\_|_|  _|\__, | _/    _\\__,_|\__|\___/ _|  _|  _|\__,_|\__|_|\___/ _|  _| 
                                                                  _ |
                                                                |__ |
                               .______________________________________________________|_._._._._._._._._._.
                                \_____________________________________________________|_#_#_#_#_#_#_#_#_#_|
                                                       

"""+"\n\n"+"\t\t\t\t\tMade by the best Analyst in the whole world Tomer Glik!"+"\n\n\n")
## MAIN PROGRAM
username = getpass.getuser()
def main():
    while True:
        print("Hello " + username + " What do you wish to do?")
        print("F = File hash\nI = IP/Subnet\nM = Multiple IPs (comma/space-separated)\nE = Ex-employee\nU = FQDN\nS = Search IP\nC = Add IP to exclusion list\nX = EXIT")
        choice = input("Enter choice: ").lower()

        if choice == 'x':
            print("Goodbye!")
            time.sleep(1)
            break

        # File hashes
        if choice == 'f':
            print("\nHash type:")
            print("1. MD5\n2. SHA1\n3. SHA256")
            hash_type = input("Select (1-3): ")
            
            try:
                count = int(input("How many hashes? "))
            except:
                print("Invalid number!")
                continue

            for _ in range(count):
                if hash_type == '1':
                    while True:
                        hash_val = input("Enter MD5 hash: ").strip()
                        if len(hash_val) != 32 or not hash_val.isalnum():
                            print("Invalid MD5 (must be 32 hex chars)")
                            continue
                        if is_string_in_file('md5.txt', hash_val):
                            print("Already exists!")
                            continue
                        with open('md5.txt', 'a') as f, open('md5.csv', 'a') as csv:
                            f.write(f"{hash_val}\n")
                            csv.write(f"{hash_val},md5_hct_blacklist\n")
                        log_entry('md5', hash_val, username)
                        print("Added successfully!")
                        break

                elif hash_type == '2':
                    # SHA1 implementation
                    while True:
                        hash_val = input("Enter SHA1 hash: ").strip()
                        if len(hash_val) != 40 or not hash_val.isalnum():
                            print("Invalid SHA1 (must be 40 hex chars)")
                            continue
                        if is_string_in_file('sha1.txt', hash_val):
                            print("Already exists!")
                            continue
                        with open('sha1.txt', 'a') as f, open('sha1.csv', 'a') as csv:
                            f.write(f"{hash_val}\n")
                            csv.write(f"{hash_val},sha1_hct_blacklist\n")
                        log_entry('sha1', hash_val, username)
                        print("Added successfully!")
                        break

                elif hash_type == '3':
                    # SHA256 implementation
                    while True:
                        hash_val = input("Enter SHA256 hash: ").strip()
                        if len(hash_val) != 64 or not hash_val.isalnum():
                            print("Invalid SHA256 (must be 64 hex chars)")
                            continue
                        if is_string_in_file('sha256.txt', hash_val):
                            print("Already exists!")
                            continue
                        with open('sha256.txt', 'a') as f, open('sha256.csv', 'a') as csv:
                            f.write(f"{hash_val}\n")
                            csv.write(f"{hash_val},sha256_hct_blacklist\n")
                        log_entry('sha256', hash_val, username)
                        print("Added successfully!")
                        break
        #Exclusions
        elif choice == 'c':
            ip = input("Enter IP to exclude: ").strip()
            if Check_Octate(ip)!= "IP":
                print("Invalid Format")
            elif not local_validation(ip):
                print("Local subnet addresses are already excluded.")
            elif is_excluded_ip(ip):
                print(f"The address : {ip} is already excluded by subnet policy.")
            else:
                already_excluded = False
                try:
                    with open('excluded_ips.txt', 'r') as f:
                        for line in f:
                            if ip == line.strip():
                                already_excluded = True
                                break
                except FileNotFoundError:
                    pass
                if already_excluded:
                    print(f"already in the exclusion list.")
                else:
                    with open('excluded_ips.txt', 'a') as f:
                        f.write(f"{ip}\n")
                    print(f"The address: {ip} added to the exclusion list.")
                    log_entry('excluded_ips', ip, username)
                
        # IP/Subnet
        
        elif choice == 'i':
            subnet = input("Block subnet? (y/n): ").lower()
            if subnet == 'y':
                while True:
                    seg = input("Enter subnet (e.g., 192.168.1.0/24): ").strip()
                    if not re.match(r'^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$', seg):
                        print("Invalid format")
                        continue
                    ip_part = seg.split('/')[0]
                    if Check_Octate(ip_part) != "IP" or not local_validation(ip_part) or is_excluded_ip(ip_part):
                        print("Invalid IP or local subnet")
                        continue
                    if is_string_in_file('ip.txt', seg):
                        print("Already exists!")
                        continue
                    with open('ip-subnets.csv', 'a') as csv, open('ip.txt', 'a') as f:
                        csv.write(f"{seg},ip_hct_blacklist\n")
                        f.write(f"{seg}\n")
                    log_entry('ip_subnet', seg, username)
                    print("Subnet added!")
                    break
            elif subnet == 'n':
                try:
                    count = int(input("How many IPs? "))
                except ValueError:
                    print("Invalid number!")
                for _ in range(count):
                    while True:
                        ip = input("Enter IPv4: ").strip()
                        if Check_Octate(ip) != "IP" or not local_validation(ip) or is_excluded_ip(ip):
                            print("Ze ip Shelano Tipesh Metomtam! (or you enterd Invalid ip)")
                            continue
                        if is_ip_in_exclusion_file(ip):
                            print(f"The address: {ip} is in the exclusion list and cannot be blocked.")
                            continue
                        if is_string_in_file('ip.txt', ip):
                            print("Already exists!")
                            continue
                        with open('ip.csv', 'a') as csv, open('ip.txt', 'a') as f:
                            csv.write(f"{ip},ip_hct_blacklist\n")
                            f.write(f"{ip}\n")
                        log_entry('ip', ip, username)
                        print("IP added!")
                        break
            else:
                print("invalid input. Exiting")
                continue
        elif choice == 'm':
            raw_ips = input("Enter multiple IPs (comma/space-separated): ").strip()
            ip_list = re.split(r'[,\s]+', raw_ips)  # Split on commas and spaces
            valid_ips = []
 
            for ip in ip_list:
                if Check_Octate(ip) == "IP" and local_validation(ip) and not is_excluded_ip(ip):  # Validate IP with exclusion
                    if not is_string_in_file('ip.txt', ip):  # Check duplicates
                        valid_ips.append(ip)
                    else:
                        print(f"Skipping duplicate: {ip}")
                else:
                    print(f"Invalid IP: {ip}")
 
            if valid_ips:
                with open('ip.csv', 'a') as csv_file, open('ip.txt', 'a') as txt_file:
                    for ip in valid_ips:
                        csv_file.write(f"{ip},ip_hct_blacklist\n")
                        txt_file.write(f"{ip}\n")
                        log_entry('ip', ip, username)
                print(f"Added {len(valid_ips)} new IPs.")
            else:
                print("No new valid IPs were added.")
        # Ex-employee
        elif choice == 'e':
            while True:
                emp = input("Enter employee (First.Last): ").strip().lower()
                if not check_emp_format(emp):
                    continue
                email = f"{emp}@example.co.il"
                if is_string_in_file('EX.txt',emp):
                        print("Already exists!")
                        break
                try:
                    os.makedirs(r"example directory", exist_ok=True)
                    with open(r"example path.csv", 'a') as f:
                        f.write(f"{emp},Ex employee\n{email},Ex employee\n")
                    with open('EX.txt', 'a') as f:
                        f.write(f"{emp}\n")
                    log_entry('ex_employee', emp, username)
                    log_entry('ex_employee', email, username)
                    print("Employee added!")
                    time.sleep(1)
                    break            
                except Exception as e:
                    print(f"Error: {str(e)}")
                    time.sleep(2)

        # FQDN
        elif choice == 'u':
            try:
                count = int(input("How many FQDNs? "))
            except:
                print("Invalid number!")
                continue
            
            for _ in range(count):
                while True:
                    fqdn = input("Enter FQDN: ").strip().lower()
                    if fqdn.startswith("www."):
                        print("FQDN must not start with 'www.'.Enter base domain only.")
                        continue
                    if not is_valid_fqdn(fqdn):
                        print(f" Invalid FQDN: ' {fqdn}'. Please enter a valid fully-qualified domain name and not bulltshit")
                        continue
                    if is_string_in_file('fqdn.txt', fqdn):
                        print("Already exists!")
                        time.sleep(1)
                        continue
                    with open('fqdn.csv', 'a') as csv, open('fqdn.txt', 'a') as f:
                        csv.write(f"{fqdn},fqdn_hct_blacklist\n")
                        f.write(f"{fqdn}\n")
                    log_entry('fqdn', fqdn, username)
                    print("FQDN added!")
                    time.sleep(1)
                    break

        # Search IP
        elif choice == 's':
            ips = input("Enter IPs to search (space-separated): ").split()
            found = []
            try:
                with open('ip.txt', 'r') as f:
                    existing = [line.strip() for line in f]
                for ip in ips:
                    if ip in existing:
                        found.append(ip)
                if found:
                    print("Found:", ', '.join(found))
                    time.sleep(2)
                else:
                    print("No matches found")
                    time.sleep(1)
            except FileNotFoundError:
                print("IP database missing")
        elif choice == '':
            print("What is wrong with you?, are you senile? CHUUU?")


        else:
            print(username +
                "\nTipesh Metotam\n"
                "There is no such letter in the script!\n"
                "Are you blind?!\n"
                "Now press ENTER and think about what you’ve done!..... ")
            time.sleep(2)
        time.sleep(2)

        os.system('cls' if os.name == 'nt' else 'clear')
    
    print(username + " Come to the jacuzzi, we'll drink wine and talk about your promotion darling")
    time.sleep(5)
if __name__ == "__main__":
    main()
