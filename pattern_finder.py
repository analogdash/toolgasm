import pefile
from os import listdir

def truncate_pedata (pedata):
    i = len(pedata)
    i -= 1
    while(pedata[i] == 0):
        i-= 1
    return pedata[0:i+1]

def loadinfo(sample_path):
    filenames = listdir(sample_path)
    file_list = [{"filename": item} for item in filenames]
    for item in file_list:
        item["path"] = sample_path + r'\\' + item["filename"]
        item["pe"] = pefile.PE(item["path"])
    return file_list

def get_pattern(file_list, max_sled):
    masterlist = []
    for exeindex in range(0, len(file_list)):
        exepath = file_list[exeindex]["path"]
        pe = file_list[exeindex]["pe"]
        pedata = pe.get_data(pe.OPTIONAL_HEADER.AddressOfEntryPoint, 4096)
        if len(pedata) == 0:
            masterlist = "WALA"
            break
        if len(pedata) != 4096:
            pedata = truncate_pedata(pedata)
        blocks = [{"ip":ip, "filter":pedata[ip:ip+max_sled]} for ip in range(0, len(pedata) - max_sled + 1)]
        if exeindex == 0:
            for prospect in blocks:
                if any(entry["filter"] == prospect["filter"] for entry in masterlist):
                    for entry in masterlist:
                        if entry["filter"] == prospect["filter"]:
                            entry["locs"] += [{"path":exepath, "ip":prospect["ip"]}]
                else:
                    masterlist.append({"filter" : prospect["filter"], "locs" : [{"path":exepath, "ip":prospect["ip"]}]})
        else:
            newlist = []
            for prospect in blocks:
                if any(entry["filter"] == prospect["filter"] for entry in masterlist):
                    if any(entry["filter"] == prospect["filter"] for entry in newlist):
                        for newentry in newlist:
                            if newentry["filter"] == prospect["filter"]:
                                newentry["locs"] += {"path":exepath, "ip":prospect["ip"]}
                    else:
                        newlist.append({"filter" : prospect["filter"], "locs" : [{"path":exepath, "ip":prospect["ip"]}] + next(entry["locs"] for entry in masterlist if entry["filter"] == prospect["filter"])})
            masterlist = newlist
        if masterlist == []:
            break
    return masterlist


sample_path = r'C:\samples'

file_list = loadinfo(sample_path)

masterlist = get_pattern(file_list,48)

len(masterlist)

for entry in masterlist:
    print(entry["filter"].hex())

index = 4
lol = 0
for loc in masterlist[index]["locs"]:
    lol+=1

