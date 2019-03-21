import requests
import safebrowsing 


#pip install requests
#pip install whois

#VirusTotal API
#https://www.virustotal.com/en/documentation/public-api/
#https://developers.virustotal.com/v2.0/reference

#Chrome SafeBrowsing API
#https://developers.google.com/safe-browsing/v4/lookup-api

#malicious
urltest = "http://persons.ipq.co/att/attiinnddeexx.html"

#clean
urltest = "http://www.google.com"

r = requests.get(urltest)



#DELET THIS
g_apikey = "GOOG API KEY HERE"
vt_apikey = "VT API KEY HERE"

#========================================Google SafeBrowsing
#Init
sb = safebrowsing.LookupAPI(g_apikey)
#Usage
resp = sb.threat_matches_find(urltest)


#========================================VirusTotal
#init
from virustotal import vt
vt = vt()
vt.setkey(vt_apikey)
#usage
vt.geturl(urltest)
vt.getip('1.1.1.1')
vt.getdomain('github.com')