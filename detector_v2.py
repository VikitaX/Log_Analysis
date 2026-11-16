import datetime

def timestamp(line):
    extract_timestamp = line.split()[0:3] #Extracts the timestamp from the log line
    join_timestamp = ' '.join(extract_timestamp) #Joins the extracted timestamp into a single string
    year = datetime.datetime.now().year  
    timestamp_object = datetime.datetime.strptime(f"{year} {join_timestamp}", '%Y %b %d %H:%M:%S')
    return timestamp_object

def get_username(line):
    splitLine = line.split() 
    i = splitLine.index('for') 
    if splitLine[i + 1] == 'invalid':
        return splitLine[i + 3] #Collects username for invalid user
    return splitLine[i + 1] #Collects username for valid user

def key_dictionary(line):
    ip = line.split()[-4] #Collects IP
    timestamp_object = timestamp(line) #Calls the timestamp function to get the timestamp object
    username = get_username(line) #Calls the get_username function to get the username
    
    filtered_dict = {'ip': ip, 'timestamp': timestamp_object, 'username': username} #Creates a dictionary with the IP address, timestamp, and username
    return filtered_dict #Returns the dictionary with the IP address, timestamp, and username

#Function to detect failed login attempts from the auth.log file
def detect_failed_logins(file):
    ip_dict = {} #dictionary to store IP addresses and their failed login attempt counts
    for line in file:
        if 'Failed password' in line:
            attempted_dict = key_dictionary(line)
            ip = attempted_dict['ip']
            event = {'timestamp': attempted_dict['timestamp'], 'username': attempted_dict['username']}
            if ip in ip_dict:
                ip_dict[ip].append(event)
            else:
                ip_dict[ip] = [event]

    return ip_dict #return dictionary of IP addresses and their failed login attempt counts

#Report Function
def report(ip_dict, threshold):
    print("REPORT OF FAILED LOGIN ATTEMPTS")
    print("----------------------------------")
    print(f"Total Failed Login Attempts: {sum(len(timestamps) for timestamps in ip_dict.values())}") #Total number of failed login attempts
    print("----------------------------------")
    for ip in ip_dict:
        if len(ip_dict[ip]) >= threshold: #Checks if the failed login attempt count for the IP address meets or exceeds the threshold
            print(f"IP {ip} has {len(ip_dict[ip])} failed login attempts.")
       
#Detailed Report Function
def detailed_report(ip_dict, threshold):
    print("\nDETAILED REPORT OF FAILED LOGIN ATTEMPTS")
    print("----------------------------------")
    for ip in ip_dict:
        if len(ip_dict[ip]) >= threshold: #Checks if the failed login attempt count for the IP address meets or exceeds the threshold
            print(f"\nIP {ip} has {len(ip_dict[ip])} failed login attempts.")
            print("Timestamps of failed attempts:")
            for timestamp in ip_dict[ip]:
                print(f"- {timestamp}")

    print("----------------------------------")
    print("REPORT OF TARGETED USERNAMES")
    print("----------------------------------")
    
                
def main():
    threshold = 5 #Threshold for failed login attempts
    
    try:
        with open("auth.log", 'r') as auth:
            ip_dict = detect_failed_logins(auth)
            report(ip_dict, threshold)
            detailed_report(ip_dict,threshold)
    except FileNotFoundError:
        print("Error: The file 'auth.log' was not found.")

main()