import requests
import csv
import time

def query_vt_hash(hash):
    time.sleep(15)
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': 'VT API KEY HERE', 'resource': hash}
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

csvpath = r"names.csv"
csvpath2 = r"names2.csv"

#main:

with open(csvpath, "r", encoding='utf-8') as csvfile:
    csreader = csv.DictReader(csvfile)
    fieldnames = csreader.fieldnames
    file_list = [row for row in csreader]

sketch_hashes = set()
for eml in file_list:
    hashes = eval(eml["attachment_hashes"]) # WARNING eval()
    for hash in hashes:
        sketch_hashes.add(hash) 

#"63998c3a64c5f896c8cdf140c62c3ca2487eb136" # no match
#"6f13dbdf05d15f0fdd300e8d2394d3212216e6eb" # lots match
#"60733de225b5c4bfc42fb79e5d1a4f6683243e4a" # clean

#sketch_hashes = [{"hash":"63998c3a64c5f896c8cdf140c62c3ca2487eb136"},{"hash":"6f13dbdf05d15f0fdd300e8d2394d3212216e6eb"},{"hash":"60733de225b5c4bfc42fb79e5d1a4f6683243e4a"}]

#dict_keys(['scans', 'scan_id', 'sha1', 'resource', 'response_code', 'scan_date', 'permalink', 'verbose_msg', 'total', 'positives', 'sha256', 'md5'])

i = 1
j = len(sketch_hashes)
for hash in sketch_hashes:
    print("Now on " + str(i) + " of " + str(j))
    response = query_vt_hash(hash)
    
    if response.status_code == 200:
        if response.json()["response_code"] == 0:
            for eml in file_list:
                if hash in eval(eml["attachment_hashes"]):
                    eml["attachment_response_status"] = "Not Found"
        elif response.json()["response_code"] == 1:
            for eml in file_list:
                if hash in eval(eml["attachment_hashes"]):
                    eml["attachment_response_status"] = "Found"
                    eml["positives"] = response.json()["positives"]
                    if eml["positives"] > 0:
                        eml["suspected"] = "Spam"
        else:
            for eml in file_list:
                if hash in eval(eml["attachment_hashes"]):
                    eml["attachment_response_status"] = "Unknown"
    
    i+=1

with open(r'names2.csv', 'w', newline='', encoding='utf-8', errors='replace') as csvfile:
    fieldnames += ["attachment_response_status", "positives"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for eml in file_list:
        writer.writerow(eml)


