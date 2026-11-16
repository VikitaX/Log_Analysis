threshold = 5

#Function to detect failed login attempts from the auth.log file
def detect_failed_logins(file):
    ip_dict = {} #dictionary to store IP addresses and their failed login attempt counts
    for line in file:
        if 'Failed password' in line:
            ip = line.split()[-4] #Collects IP
            if ip in ip_dict:
                ip_dict[ip] += 1 #Adds 1 to the count of failed login attempts for that IP address
            else:
                ip_dict[ip] = 1 #Initializes the count of failed login attempts for that IP address to 1

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
    