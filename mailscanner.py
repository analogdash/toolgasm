import email
from email import policy
from email.parser import BytesParser
from os import path
from os import listdir
import csv
import re
import requests
import json

def query_safebrowsing(urllist):
    apiurl = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=API_KEY"
    requestbody = {
        "client": {
            "clientId":      "mailscanner",
            "clientVersion": "0.0.1"
        },
        "threatInfo": {
            "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION", "UNWANTED_SOFTWARE"],
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": urllist
        }
    }
    return requests.post(apiurl, data = json.dumps(requestbody))

def process(sample_path):

    filenames = listdir(sample_path)
    
    file_list = [{"filename": item} for item in filenames]
    
    #senders = set()
    
    for eml in file_list:
    
        #EML File properties
        eml["path"] = sample_path + r'\\' + eml["filename"]
        eml["filesize"] = path.getsize(eml["path"])
        
        with open(eml["path"], 'rb') as fp:
            msg = BytesParser(policy=policy.default).parse(fp)
        
        #Receivers
        receivers = [item[1] for item in msg.items() if item[0] == "Received"]
        eml["receivers_n"] = len(receivers)
        if len(receivers) > 0:
            eml["last_receiver"] = receivers[-1]
        
        #Working on senders
        eml["from_raw"] = msg["from"]
        eml["from_addresses"] = set(re.findall(r'[a-zA-Z0-9._&%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24}', eml["from_raw"]))
        eml["from_n_emails"] = len(eml["from_addresses"])
        #senders.update(eml["from_addresses"])
        eml["from_domains"] = set()
        for addr in eml["from_addresses"]:
            eml["from_domains"].add(addr.split("@")[1])
        
        eml["to"] = msg["to"]
        
        # Check if Reply-To is same as From
        if msg["reply-to_raw"]:
            eml["reply-to_raw"] = msg["reply-to_raw"]
            eml["reply-to_addresses"] = set(re.findall(r'[a-zA-Z0-9._&%\'+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24}', msg["reply-to_raw"]))
            eml["reply-to_n"] = len(eml["reply-to_addresses"])
            eml["reply-to_is_same"] = 0
            for reply_add in eml["reply-to_addresses"]:
                if eml["from_raw"].find(reply_add) != -1:
                    eml["reply-to_is_same"] = 1+
        
        eml["subject"] = msg["subject"]
        
        eml["content_type"] = msg.get_content_type()

        #if eml["content_type"] == "text"
    #sender_domains = set()
    #for sender in senders:
    #    sender_domains.add(sender.split("@")[1])
    #CHECK GOOGLE SAFEBROWSING
    #sender_domain_list = [{"url": domain} for domain in sender_domains]
    #ret = query_safebrowsing(sender_domain_list)
    #Check UFO LISt
    #with open('5809f3509d3fb4065a46d602.csv', 'r') as csvfile:
    #    uforeader = csv.reader(csvfile)
    #    ufoset = set([row[1] for row in uforeader if row[0] == "domain"])
    #bad_ufo = sender_domains.intersection(ufoset)
    
    #Output to file
    with open('names.csv', 'w', newline='', encoding='utf-8', errors='replace') as csvfile:
        fieldnames = ["suspected", "path", "filename", "filesize",
                      "last_receiver", "receivers_n",
                      "from_raw", "from_addresses", "from_n_emails", "from_domains",
                      "reply-to_raw","reply-to_addresses", "reply-to_n", "reply-to_is_same",
                      "to",
                      "subject",
                      "content_type"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for eml in file_list:
            writer.writerow(eml)

sample_path = r""

senders = process(sample_path)
#filename = r""
#with open(filename, 'rb') as fp:
#    msg = BytesParser(policy=policy.default).parse(fp)
