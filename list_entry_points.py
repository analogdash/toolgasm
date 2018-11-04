import pefile
from os import listdir

def loadinfo(sample_path):
    filenames = listdir(sample_path)
    file_list = [{"filename": item} for item in filenames]
    for item in file_list:
        item["path"] = sample_path + r'\\' + item["filename"]
        item["pe"] = pefile.PE(item["path"])
    return file_list

sample_path = r'C:\samples'

file_list = loadinfo(sample_path)

f = open("demofile.csv", "a")
f.write("filename")
f.write(",")
f.write("ep")
f.write(",")
f.write("imagebase")
f.write(",")
f.write("no of sections")
f.write(",")
f.write("first hex bytes")
f.write("\n")

for item in file_list:
    f.write(item["filename"])
    f.write(",")
    f.write(hex(item["pe"].OPTIONAL_HEADER.AddressOfEntryPoint))
    f.write(",")
    f.write(hex(item["pe"].OPTIONAL_HEADER.ImageBase))
    f.write(",")
    f.write(len(item["pe"].sections))
    f.write(",")
    f.write(item["pe"].get_data(item["pe"].OPTIONAL_HEADER.AddressOfEntryPoint, 16).hex())
    f.write("\n")

f.close()

