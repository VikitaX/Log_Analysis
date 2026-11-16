import datetime

threshold = 5

def timestamp():
    extract_timestamp = line.split()[0:3] #Extracts the timestamp from the log line
    join_timestamp = ' '.join(extract_timestamp) #Joins the extracted timestamp into a single string
    timestamp_object = datetime.datetime.strptime(join_timestamp, '%b %d %H:%M:%S') #Converts the timestamp string into a datetime object
    return timestamp_object

def ip_and_timestamp(line):
    ip = line.split()[-4] #Collects IP
    timestamp_object = timestamp() #Calls the timestamp function to get the timestamp object
    filtered_dict = {'ip': ip, 'timestamp': timestamp_object} #Creates a dictionary with the IP address and timestamp
    return filtered_dict #Returns the dictionary with the IP address and timestamp

#Function to detect failed login attempts from the auth.log file
def detect_failed_logins(file):
    ip_dict = {} #dictionary to store IP addresses and their failed login attempt counts
    for line in file:
        if 'Failed password' in line:
            filtered_dict = ip_and_timestamp(line) 
            ip = filtered_dict['ip']
            if ip in ip_dict:
                ip_dict[ip] += filtered_dict['timestamp']
            else:
                ip_dict[ip] = filtered_dict['timestamp']

    return ip_dict #return dictionary of IP addresses and their failed login attempt counts

#Report Function
def report(ip_dict):
    print("REPORT OF FAILED LOGIN ATTEMPTS")
    print("----------------------------------")
    print(f"Total Failed Login Attempts: {sum(ip_dict.values())}") #Total number of failed login attempts
    print("----------------------------------")
    for ip in ip_dict:
        if ip_dict[ip] >= threshold: #Checks if the failed login attempt count for the IP address meets or exceeds the threshold
            print(f"IP {ip} has {ip_dict[ip]} failed login attempts.")



try:
    with open("auth.log", 'r') as auth:
        ip_dict = detect_failed_logins(auth)
        report(ip_dict)
   
except FileNotFoundError:
    print("Error: The file 'auth.log' was not found.")
    