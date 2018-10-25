import subprocess
import pefile
from os import listdir

##########
# IMPORTANT: strings.exe needs to be run at least once on a system to accept the EULA
##########

def get_strings (exepath):
    #### CHANGE THIS TO THE PATH OF strings.exe from Sysinternals
    stringspath = r'C:\strings.exe'
    maxchars = 16
    pe = pefile.PE(exepath)
    outputlist = subprocess.Popen([stringspath, "-o", "-n", str(maxchars), "-nobanner", exepath], stdout=subprocess.PIPE).stdout.read().decode("utf-8").splitlines()
    return [{"offset" : int(item.split(":", 1)[0]), 
             "virtadd" : pe.get_offset_from_rva(int(item.split(":", 1)[0])), 
             "string" : item.split(":", 1)[1]} for item in outputlist]


def get_common_strings (sample_path):
    file_list = [sample_path + r'\\' + item for item in listdir(sample_path)]
    all_strings = [{"path" : item, "string_list" : get_strings(item)} for item in file_list]
    masterlist = []
    for sample in all_strings:
        for hit in sample["string_list"]:
            if any(entry["string"] == hit["string"] for entry in masterlist):
                for entry in masterlist:
                    if entry["string"] == hit["string"]:
                        entry["hits"] += 1
                        entry["locations"].append({"filepath" : sample["path"], "offset" : hit["offset"], "virtadd" : hit["virtadd"]})
            else:
                masterlist.append({"string": hit["string"], "hits" : 1, "locations" : [{"filepath" : sample["path"], "offset" : hit["offset"], "virtadd" : hit["virtadd"]}]})
    ultracommon = []
    for entry in masterlist:
        if entry["hits"] == len(file_list):
            ultracommon.append(entry)
    return ultracommon

sample_path = r'C:\samples'
common_strings = get_common_strings(sample_path)

len(common_strings)

for hit in common_strings:
    print(hit["string"])
