import csv
import socket

#functions

def gimme_ip(host):




#data:

csvpath = r"names2.csv"
csvpath2 = r"names3.csv"

#main:

with open(csvpath, "r", encoding='utf-8') as csvfile:
    csreader = csv.DictReader(csvfile)
    fieldnames = csreader.fieldnames
    file_list = [row for row in csreader]

sketch_senders = set()
for eml in file_list:
    domains = eval(eml["from_domains"]) # WARNING eval()
    for dom in domains:
        sketch_senders.add(dom) 

sketch_senders = [{"domain": dom} for dom in sketch_senders]

for dom in sketch_senders:
    ip = gimme_ip(dom)


i = 1
j = len(sketch_hashes)
for hash in sketch_hashes:
    print("Now on " + str(i) + " of " + str(j))
    response = query_vt_hash(hash)
    print("response is " + str(response.status_code))
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
    time.sleep(15)
    i+=1

with open(r'names2.csv', 'w', newline='', encoding='utf-8', errors='replace') as csvfile:
    fieldnames += ["attachment_response_status", "positives"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for eml in file_list:
        writer.writerow(eml)


