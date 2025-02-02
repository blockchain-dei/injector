import subprocess
import re
import sys
import os
import csv

save_to = "./tests/"
r = re.compile(".*pragma")
r1 = re.compile(".*.sol")
remove_words = ['pragma', 'solidity', '^', '>', '=', '<', ';','\n']
tool = sys.argv[1]
directory = sys.argv[2]
csv_header = ["contract name","tool","vulnerability name","line","code"] #nº de vezes que aconteceu, em que linhas

def getlinevalue(line):
    arr_values = line.split(":", 1)
    value = arr_values[1].strip()
    return value

class Vulnerability:
  name = ""
  line = ""
  code = ""

def getSlitherLineCode(line):
    m = re.split(r'#(.+?)[)]+', line)
    return m[-2]      

def slitherParser(arr_lines):
    arr_vuln = []
    current_line = 0
    aux_current_line = 0
    for line in arr_lines:
        current_line += 1
        aux_current_line = current_line
        if "INFO:Detectors:" in line:
            aux_arr_vulns = []
            while "Reference:" not in arr_lines[aux_current_line] :
                newvuln = arr_lines[aux_current_line]
                if newvuln.startswith("Reentrancy in"):
                    aux_current_line += 2
                    vuln = Vulnerability()
                    vuln.code = arr_lines[aux_current_line].replace("\n","")
                    vuln.line = getSlitherLineCode(vuln.code)
                    aux_arr_vulns.append(vuln)
                    while aux_current_line < len(arr_lines):
                        if "Reference:" in arr_lines[aux_current_line + 1]:
                            break
                        aux_current_line += 1
                elif newvuln.startswith("\t-") == False and newvuln.endswith(":\n") == False and newvuln.find("#") != -1:
                    vuln = Vulnerability()
                    vuln.code = newvuln.replace("\n","")
                    vuln.line = getSlitherLineCode(vuln.code)
                    aux_arr_vulns.append(vuln)
                elif newvuln.startswith("\t-") and newvuln.find("#") != -1:
                    vuln = Vulnerability()
                    vuln.code = newvuln.replace("\t", "").replace("\n","")
                    vuln.line = getSlitherLineCode(vuln.code)
                    aux_arr_vulns.append(vuln)
                aux_current_line += 1
            else :
                for vuln in aux_arr_vulns:
                    vuln.name = getlinevalue(arr_lines[aux_current_line]).replace("[0m", "")
            arr_vuln.extend(aux_arr_vulns)
    return arr_vuln

def securifyParser(arr_lines):
    counter = 0
    arr_vuln = []
    current_line = 0
    aux_current_line = 0
    for line in arr_lines:
        current_line += 1
        aux_current_line = current_line
        if "Pattern:" in line:
            vuln = Vulnerability()
            vuln.name = getlinevalue(line)
            arr_vuln.append(vuln)
            counter += 1
        elif "Line:" in line:
            vuln = arr_vuln[counter-1]
            vuln.line = getlinevalue(line)
        elif "Source:" in line:
            vuln = arr_vuln[counter-1]
            while ">" in arr_lines[aux_current_line] :
                #print(arr_lines[aux_current_line])
                if arr_lines[aux_current_line].find("^") != -1 and arr_lines[aux_current_line].find(";") == -1:
                    vuln.code = arr_lines[aux_current_line - 1].replace("\n", "").replace("\t", "")
                    break
                aux_current_line += 1
    return arr_vuln

def mythrilParser(arr_lines):
    counter = 0
    arr_vuln = []
    current_line = 0
    for line in arr_lines:
        current_line += 1
        if "SWC ID:" in line:
            vuln = Vulnerability()
            vuln.name = line.replace("\n", "")
            arr_vuln.append(vuln)
            counter += 1
        elif "In file:" in line:
            vuln = arr_vuln[counter-1]
            vuln.line = line.split(":")[2].replace("\n", "")
            vuln.code = arr_lines[current_line + 1].replace("\n", "")
    return arr_vuln

def parseResults(contract, result):
    arr_lines = result.readlines()
    csv_lines = []
    arr_vulnerabilities = []
    if tool == "securify":
        arr_vulnerabilities = securifyParser(arr_lines)
    elif tool == "slither":
        arr_vulnerabilities = slitherParser(arr_lines)
    elif tool == "myth analyze":
        arr_vulnerabilities = mythrilParser(arr_lines)
    for vulnerability in arr_vulnerabilities:
        line = [contract, tool, vulnerability.name, vulnerability.line, vulnerability.code] # csv_header
        csv_lines.append(line)
    #print(csv_lines)
    return csv_lines

def saveFinalCsv(csv_lines):
    with open(save_to + tool + "_" + ".csv", 'w+', newline='', encoding='utf8') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerows(csv_lines)

def checkVersion(contract):
    with open(directory+contract) as f:
        contents = f.readlines()
        versionlist = list(filter(r.match, contents))
        if len(versionlist) > 0:
            version = versionlist[0]
            for word in remove_words:
                version = version.replace(word, "")
            return version.split()[0]
            #if ((version.split()[0] ==  '0.4.16') or (version.split()[0] ==  '0.4.17') or (version.split()[0] ==  '0.4.18') or (version.split()[0] ==  '0.4.19') or  (version.split()[0] ==  '0.4.20') or  (version.split()[0] ==  '0.4.21') or (version.split()[0] ==  '0.4.22') or (version.split()[0] ==  '0.4.23') ):
            #    return '0.4.23'
            #else:
	            
    return

def main(vulnerable_list):
    current_version = ""
    no_pragma = []
    errors = []
    csv_lines = [csv_header]
    for contract in vulnerable_list:
        print("")
        print(contract)
        version = checkVersion(contract)
        print(version)
        if version:
            if current_version != version:
                current_version = version
                subprocess.call("solc-select use " + version, shell=True )
            cmd = tool + " " + directory + contract
            print(cmd)
            logfile_dir = save_to + contract + ".txt"
            with open(logfile_dir, "wb+") as logfile:
                result = subprocess.run(cmd, shell=True, stdout=logfile, stderr=logfile)
                return_code = result.returncode
                print("RESULT :: " + str(return_code))
                if return_code == 255 or return_code == 1:
                    errors.append(contract)
            with open(logfile_dir, "r") as logfile:
                csv_lines += parseResults(contract, logfile)
        else:
            print("No sol version!")
            no_pragma.append(contract)
    saveFinalCsv(csv_lines)
    print("")
    print(":: FINISHED ::\n")
    print("Contracts with missing pragma version: " + str(no_pragma) + "\n")
    print("Contracts that might have compiler errors: " + str(errors) + "\n")

if __name__ == '__main__':
    vulnerable_list = list(filter(r1.match, os.listdir(directory)))
    vulnerable_list.sort()
    print("Contracts being analyzed: " + str(vulnerable_list))
    print("")
    main(vulnerable_list)
