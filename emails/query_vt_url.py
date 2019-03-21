import requests
import csv
import time

#functions

def query_vt_url(link):
    time.sleep(15)
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': 'VT API KEY HERE', 'resource': link}
    retry_on_exceptions = ( 
         requests.exceptions.Timeout,
         requests.exceptions.ConnectionError,
         requests.exceptions.HTTPError
    )
    for i in range(30):
        try:    
            response = requests.get(url, params=params)
        except retry_on_exceptions:
            print("Trying again " + str(i))
            time.sleep(15)
            continue
        else:
            print("response is " + str(response.status_code))
            return response
    else:
        print("FAIL")
    
    return response


#data:

csvpath = r"names3.csv"
csvpath2 = r"names4.csv"

#main:

with open(csvpath, "r", encoding='utf-8') as csvfile:
    csreader = csv.DictReader(csvfile)
    fieldnames = csreader.fieldnames
    file_list = [row for row in csreader]

sketch_links = set()
for eml in file_list:
    domains = eval(eml["domains"]) # WARNING eval()
    for dom in domains:
        if dom != "":
            sketch_links.add(dom) 

#sketch_links = [{"domain": dom} for dom in sketch_links]

#for dom in sketch_links:
    #ip = gimme_ip(dom)


i = 1
j = len(sketch_links)
for link in sketch_links:
    print("Now on " + str(i) + " of " + str(j))
    response = query_vt_url(link)
    #print("response is " + str(response.status_code))
    if response.status_code == 200:
        if response.json()["response_code"] == 0:
            for eml in file_list:
                if link in eval(eml["domains"]):
                    eml["domain_status"] = "Not Found"
        elif response.json()["response_code"] == 1:
            for eml in file_list:
                if link in eval(eml["domains"]):
                    eml["domain_status"] = "Found"
                    eml["domain_positives"] = response.json()["positives"]
                    if eml["domain_positives"] > 0:
                        eml["suspected"] = "Spam"
        else:
            for eml in file_list:
                if link in eval(eml["domains"]):
                    eml["domain_status"] = "Unknown"
    i+=1

with open(csvpath2, 'w', newline='', encoding='utf-8', errors='replace') as csvfile:
    fieldnames += ["domain_status", "domain_positives"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for eml in file_list:
        writer.writerow(eml)


