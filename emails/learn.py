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
import numpy as np
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
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

def strip_text(text):
    lines = (line.strip() for line in text.splitlines())
    chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
    text = '\n'.join(chunk for chunk in chunks if chunk)
    return text

def strip_tags(body_text):
    soup = BeautifulSoup(body_text, features="html.parser")
    for script in soup(["script", "style"]):
        script.extract()
    text = soup.get_text()
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

def levenshtein(seq1, seq2):  
    size_x = len(seq1) + 1
    size_y = len(seq2) + 1
    matrix = np.zeros ((size_x, size_y))
    for x in range(size_x):
        matrix [x, 0] = x
    for y in range(size_y):
        matrix [0, y] = y
    for x in range(1, size_x):
        for y in range(1, size_y):
            if seq1[x-1] == seq2[y-1]:
                matrix [x,y] = min(
                    matrix[x-1, y] + 1,
                    matrix[x-1, y-1],
                    matrix[x, y-1] + 1
                )
            else:
                matrix [x,y] = min(
                    matrix[x-1,y] + 1,
                    matrix[x-1,y-1] + 1,
                    matrix[x,y-1] + 1
                )
    print (matrix)
    return (matrix[size_x - 1, size_y - 1])
    
hampath = r"\Normal"
spampath = r"\Spam"
ham_filenames = listdir(hampath)
spam_filenames = listdir(spampath)

file_list = [{"filename": item, "type":"spam"} for item in spam_filenames] + [{"filename": item, "type":"ham"} for item in ham_filenames]

for eml in file_list:
    if eml["type"] == "spam":
        eml["path"] = spampath + r'\\' + eml["filename"]
    elif eml["type"] == "ham":
        eml["path"] = hampath + r'\\' + eml["filename"]
    
    with open(eml["path"], 'rb') as fp:
        msg = BytesParser(policy=policy.default).parse(fp)
    
    eml["wordsoup"] = []
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            eml["wordsoup"] += make_words(strip_text(part.get_content()))
        elif part.get_content_type() == "text/html":
            eml["wordsoup"] += make_words(strip_tags(part.get_content()))

            
#file_list[-1]["wordsoup"][0]

#lol = levenshtein(file_list[-1]["wordsoup"][0], file_list[-1]["wordsoup"][1])
