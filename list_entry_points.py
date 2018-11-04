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

for item in file_list:
    f.write(item["filename"],",",hex(item["pe"].OPTIONAL_HEADER.AddressOfEntryPoint))

