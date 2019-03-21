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
    apiurl = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=GOOG API KEY HERE"
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
    senders = set()
    for eml in file_list:
        eml["path"] = sample_path + r'\\' + eml["filename"]
        eml["filesize"] = path.getsize(eml["path"])
        with open(eml["path"], 'rb') as fp:
            msg = BytesParser(policy=policy.default).parse(fp)
        receivers = [item[1] for item in msg.items() if item[0] == "Received"]
        if len(receivers) > 0:
            eml["last_receiver"] = receivers[-1]
        matches = set(re.findall(r'[a-zA-Z0-9._&%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24}', msg["from"]))
        senders.update(matches)
        eml["from"] = msg["from"]
        eml["to"] = msg["to"]
        # Check if Reply-To is same as From
        if msg["reply-to"]:
            eml["reply-to"] = msg["reply-to"]
            eml["set_reply-to"] = set(re.findall(r'[a-zA-Z0-9._&%\'+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24}', msg["reply-to"]))
            eml["n_reply-to"] = len(eml["set_reply-to"])
            eml["same_reply-to"] = 0
            for reply_add in eml["set_reply-to"]:
                if eml["from"].find(reply_add) != -1:
                    eml["same_reply-to"] = 1
        eml["subject"] = msg["subject"]
        eml["n_receivers"] = str(len(receivers))
        eml["content_type"] = msg.get_content_type()
        eml["n_emails"] = len(matches)
        if eml["content_type"] == "text"
    sender_domains = set()
    for sender in senders:
        sender_domains.add((sender.split("@")[1]))
    #CHECK GOOGLE SAFEBROWSING
    #sender_domain_list = [{"url": domain} for domain in sender_domains]
    #ret = query_safebrowsing(sender_domain_list)
    #Check UFO LISt
    #with open('5809f3509d3fb4065a46d602.csv', 'r') as csvfile:
    #    uforeader = csv.reader(csvfile)
    #    ufoset = set([row[1] for row in uforeader if row[0] == "domain"])
    #bad_ufo = sender_domains.intersection(ufoset)
    with open('names.csv', 'w', newline='', encoding='utf-8', errors='replace') as csvfile:
        fieldnames = ["suspected","path", "filename", "filesize", "last_receiver", "n_receivers", "from", "n_emails", "reply-to","set_reply-to", "n_reply-to", "same_reply-to", "to", "subject", "content_type"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for eml in file_list:
            writer.writerow(eml)

    
    
sample_path = r"PATH HERE"
senders = process(sample_path)

#with open(filename, 'rb') as fp:
#    msg = BytesParser(policy=policy.default).parse(fp)




