from cymon import Cymon
import json
import urllib.parse

api = Cymon('19cbd68f36262f4d7a934e24db45b09944b57ca7')


def ip_lookup():
    usr = input("Enter IP for IP object details:")
    f = open("cymon_api","w")
    f.write(json.dumps(api.ip_lookup(usr)))
def ip_events():
    usr = input("Enter IP to get security event resources:")
    f = open("cymon_api","w")
    f.write(json.dumps(api.ip_events(usr)))
def ip_domains():
    usr = input("Enter IP to get domains associated with an IP:")
    f = open("cymon_api","w")
    f.write(json.dumps(api.ip_domains(usr)))
def ip_urls():
    usr = input("Enter URL to get associated IP(s):")
    f = open("cymon_api","w")
    f.write(json.dumps(api.ip_urls(urllib.parse.quote(usr,safe=''))))
def ip_blacklist():
    usr = input("Enter tag to retrieve list of IPs that are associated with {malware, botnet, spam, phishing, malicious activity, blacklist, dnsbl}:")
    f = open("cymon_api","w")
    f.write(json.dumps(api.ip_blacklist(usr)))
def domain_lookup():
    usr = input("Enter domain name to get domain object detail:")
    f = open("cymon_api","w")
    f.write(json.dumps(api.domain_lookup(usr)))
def domain_blacklist():
    usr = input("Enter tag to retrieve list of domains that are associated with {malware, botnet, spam, phishing, malicious activity, blacklist, dnsbl}:")
    f = open("cymon_api","w")
    f.write(json.dumps(api.domain_blacklist(usr)))
def url_lookup():
    usr = input("Enter URL to get security events resource:")
    f = open("cymon_api","w")
    f.write(json.dumps(api.url_lookup(urllib.parse.quote(usr,safe=''))))

OptionSelect = {
    1: ip_lookup,
    2: ip_events,
    3: ip_domains,
    4: ip_urls,
    5: ip_blacklist,
    6: domain_lookup,
    7: domain_blacklist,
    8: url_lookup,
    0: quit
}

selection = 9

while (selection != 0):
    
    print("1: ip_lookup")
    print("2: ip_events")
    print("3: ip_domains")
    print("4: ip_urls")
    print("5: ip_blacklist")
    print("6: domain_lookup")
    print("7: domain_blacklist")
    print("8: url_lookup")
    print("0: quit")
    selection = int(input("Selection Option:"))
    if (selection >= 0) and (selection <= 8):
        OptionSelect[selection]()



