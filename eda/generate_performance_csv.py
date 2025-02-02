import re
import argparse
import os
from typing import SupportsAbs

header = "Contract name;Memory(max MB);Memory(avg MB);CPU(max %);CPU(avg %);\n"
inputs = []

#################
# CLI INTERFACE #
#################
parser = argparse.ArgumentParser(description='Generates a CSV based on the performance reports outputed by caliper.')

parser.add_argument('input', help='the logs directory')
args = parser.parse_args()

directory = args.input
for subdirectory in sorted(os.listdir(directory)):
    try:
        files = os.listdir(directory+"/"+subdirectory)
        reportfile = [file for file in files if file.startswith("report")]
        if len(reportfile) > 0:
            print(reportfile)
            try:
                with open(directory+"/"+subdirectory+"/"+reportfile[0]) as file:
                    lines = file.readlines()
                    for line in lines:
                        if line.find("<td>Process</td>") != -1:
                            revalues = re.split("<td>|</td>", line)
                            values = [item for item in revalues if item.find("MB") != -1 or item.find("%") != -1]
                            inputs.append(subdirectory
                                +";"+values[0].replace("MB", "")
                                +";"+values[1].replace("MB", "")
                                +";"+values[2].replace("%", "")
                                +";"+values[3].replace("%", "")
                                +"\n"
                            )
            except:
                pass
    except:
        pass

with open("./performance.csv", "w") as file:
    file.write(header)
    file.writelines(inputs)