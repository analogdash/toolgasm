import email
from email import policy
from email.parser import BytesParser
from os import path
from os import listdir
import csv
import re
import requests
import json
import time
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
import hashlib
import string

def make_words(text):
    text = text.lower()
    words = word_tokenize(text)
    words = [x for x in words if x not in string.punctuation]
    words = [x for x in words if x not in stopwords.words("english")]
    words = [x for x in words if len(x) > 3]
    stemmer = PorterStemmer()
    words = [stemmer.stem(word) for word in words]
    return words

def strip_tags(text):
    soup = BeautifulSoup(text, features="html.parser")
    for script in soup(["script", "style"]):
        script.extract()
    text = soup.get_text()
    lines = (line.strip() for line in text.splitlines())
    chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
    text = '\n'.join(chunk for chunk in chunks if chunk)
    return text

def strip_text(text):
    lines = (line.strip() for line in text.splitlines())
    chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
    text = '\n'.join(chunk for chunk in chunks if chunk)
    return text
    
def gimme_domain(link_url):
    data = urlparse(link_url)
    return data.netloc

def gimme_links(body_text):
    soup = BeautifulSoup(body_text, features="html.parser")
    links = []
    for link in soup.find_all('a'):
        links.append(link.get('href'))
    return links

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
        print("Now doing " + eml["filename"])
        #EML File properties
        eml["folder"] = sample_path
        eml["path"] = sample_path + '\\' + eml["filename"]
        eml["filesize"] = path.getsize(eml["path"])
        
        with open(eml["path"], 'rb') as fp:
            msg = BytesParser(policy=policy.default).parse(fp)
        
        #Receivers
        receivers = [item[1] for item in msg.items() if item[0] == "Received"]
        eml["receivers_n"] = len(receivers)
        if len(receivers) > 0:
            eml["last_receiver"] = receivers[-1]
        #use me 
        #Working on senders
        eml["from_raw"] = msg["from"]
        eml["from_realname"] = email.utils.parseaddr(msg["from"])[0]
        eml["from_emailaddress"] = email.utils.parseaddr(msg["from"])[1]
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
            eml["reply-to_is_same"] = False
            for reply_add in eml["reply-to_addresses"]:
                if eml["from_raw"].find(reply_add) != -1:
                    eml["reply-to_is_same"] = True
        
        eml["subject"] = msg["subject"]
        
        eml["date_raw"] = msg["Date"]
        eml["date_unix"] = time.mktime(email.utils.parsedate(msg["Date"]))
        eml["date_timezone"] = email.utils.parsedate_tz(msg["Date"])[9]
        
        eml["mailer"] = msg["X-Mailer"]
        
        eml["content_type"] = msg.get_content_type()
        eml["contents"] = []
        for part in msg.walk():
            eml["contents"].append(part.get_content_type())
        eml["contents_n"] = len(eml["contents"])
        
        wordsoup = []
        links = []
        eml["attachment_hashes"] = []
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                i = 1
                #wordsoup.append(make_words(strip_text(part.get_content())))
            elif part.get_content_type() == "text/html":
                links += gimme_links(part.get_content())
                wordsoup.append(make_words(strip_tags(part.get_content())))
            elif part.get_content_type() in ["application/msword", "application/octet-stream", "application/pdf", "application/x-tar", "application/java-archive", "application/x-msdownload"] :
                m = hashlib.sha1()
                m.update(part.get_content())
                eml["attachment_hashes"] += [m.hexdigest()]
        eml["domains"] = set()
        if links != []:
            for link in links:
                if link != None:
                    if link[0:6] != "mailto":
                        eml["domains"].add(link)
                        #dom = gimme_domain(link)
                        #if dom != "":
                            #eml["domains"].add(gimme_domain(link))
        
        eml["wordsoup"] = wordsoup
        
        #wordsoup
        
        eml["is_multipart"] = msg.is_multipart()

        #if eml["content_type"] == "text"
    #sender_domains = set()
    #for sender in senders:
    #    sender_domains.add(sender.split("@")[1])
    #CHECK GOOGLE SAFEBROWSING
    #
    #ret = query_safebrowsing(sender_domain_list)
    #Check UFO LISt

    #return file_list
    # sketch_domains = set()
    # for eml in file_list:
        # for dom in eml["domains"]:
            # sketch_domains.add(dom)

    #sender_domain_list = [{"url": domain} for domain in sketch_domains]
    #return query_safebrowsing(sender_domain_list)

    
    
    
    #return sketch_hashes
    #print(ret.body)

    # with open(r'ufolist.csv', 'r') as csvfile:
       # uforeader = csv.reader(csvfile)
       # ufoset = set([row[1] for row in uforeader if row[0] == "domain"])
    # bad_ufo = sketch_domains.intersection(ufoset)
    
    # with open(r"sketchy_doms.txt", "w") as fp:
        # for dom in bad_ufo:
            # fp.write(dom + "\n")
    
    #Output to file
    with open(r'mails3.csv', 'w', newline='', encoding='utf-8', errors='replace') as csvfile:
        fieldnames = ["suspected", "folder", "path", "filename", "filesize",
                      "last_receiver", "receivers_n",
                      "from_raw", "from_realname", "from_emailaddress", "from_addresses", "from_n_emails", "from_domains",
                      "reply-to_raw","reply-to_addresses", "reply-to_n", "reply-to_is_same",
                      "to",
                      "subject", 
                      "date_raw", "date_unix", "date_timezone",
                      "mailer",
                      "content_type", "contents", "contents_n", "is_multipart", "wordsoup",
                      "domains", "attachment_hashes"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for eml in file_list:
            writer.writerow(eml)
            
    return file_list

sample_path = r"path here"

ret = process(sample_path)