import csv
import shutil
import os

csvpath = r"CSV PATH"

with open(csvpath, "r", encoding='utf-8') as csvfile:
    csreader = csv.DictReader(csvfile)
    file_list = [row for row in csreader]

folders = set([eml["suspected"] for eml in file_list if eml["suspected"] != ""])

for folname in folders:
    try:
        os.mkdir(file_list[0]["folder"] + "//" + folname)
        print("Created " + folname)
    except FileExistsError:
        print(folname + " already exists")

for eml in file_list:
    if eml["suspected"] != "":
        oldfilename = eml["folder"] + "\\" + eml["filename"]
        newfilename = eml["folder"] + "\\" + eml["suspected"] + "\\" + eml["filename"]
        shutil.move(oldfilename, newfilename)
        
