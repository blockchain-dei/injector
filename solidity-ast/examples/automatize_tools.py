import os
#new_lib = '//Users/fernandovidal/Documents/Phd\ Coimbra/PublicacoesTrabalhar/SmartContract/securify2/securify/staticanalysis/libfunctors'
#if not new_lib in os.environ['LD_LIBRARY_PATH']:
#    os.environ['LD_LIBRARY_PATH'] += ':'+new_lib
#    try:
#        os.execv(sys.argv[0], sys.argv)
#    except Exception as e:
#        sys.exit('EXCEPTION: Failed to Execute under modified environment, '+e)


import subprocess
import re
import sys

import csv

#cmd = "/bin/echo $LD_LIBRARY_PATH"

#sys_env = os.environ.copy()

# We've used os.environ.copy() so we can make mods
# to the subprocess environment if needed without
# affecting the parent process.
#print(sys_env)
#print(sys.platform)
#if sys.platform == 'darwin':
    #if "LD_LIBRARY_PATH" in sys_env:
        #print("achei")
        #cmd = f"export LD_LIBRARY_PATH={sys_env['LD_LIBRARY_PATH']} && {cmd}"
#    cmd = f"export LD_LIBRARY_PATH=/Users/fernandovidal/securify2/securify/staticanalysis/libfunctors"
    #if "DYLD_LIBRARY_PATH" in sys_env:
     #   cmd = f"export DYLD_LIBRARY_PATH={sys_env['DYLD_LIBRARY_PATH']} && {cmd}"

#process = subprocess.Popen(
#    cmd,
##    env=sys_env,
#    shell=True,
#)


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
            print(version.split()[0])
            if ((version.split()[0] ==  '0.4.16') or (version.split()[0] ==  '0.4.17')):
                return '0.4.25'
            return version.split()[0]
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




#{#'PERLBREW_SHELLRC_VERSION': '0.92', 'MANPATH': '/Users/fernandovidal/perl5/perlbrew/perls/perl-5.28.0/man:/Library/Frameworks/Python.framework/Versions/3.7/share/man:/usr/local/share/man:/usr/share/man:/Library/TeX/texbin/man:/opt/X11/share/man:/Library/Apple/usr/share/man:/Library/Frameworks/Mono.framework/Versions/Current/share/man:/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/share/man:/Library/Developer/CommandLineTools/usr/share/man', 'PERLBREW_VERSION': '0.92', 'TERM_PROGRAM': 'Apple_Terminal', 'SSL_CERT_FILE': '/Library/Frameworks/Python.framework/Versions/3.7/lib/python3.7/site-packages/certifi/cacert.pem', 'PERLBREW_PERL': 'perl-5.28.0', 'SHELL': '/bin/bash', 'TERM': 'xterm-256color', 'TMPDIR': '/var/folders/g9/kqt22j6j0512rg6405m7ztym0000gn/T/', 'TERM_PROGRAM_VERSION': '440', 'OLDPWD': '/Users/fernandovidal/Documents/Phd Coimbra/PublicacoesTrabalhar/SmartContract/smartcontract-faultinjector/solidity-ast/examples/tests', 'TERM_SESSION_ID': '53142B06-A686-448D-8506-107355902754', 'USER': 'fernandovidal', 'LD_LIBRARY_PATH': ':/Users/fernandovidal/securify2/securify/staticanalysis/libfunctors', 'REQUESTS_CA_BUNDLE': '/Library/Frameworks/Python.framework/Versions/3.7/lib/python3.7/site-packages/certifi/cacert.pem', 'SSH_AUTH_SOCK': '/private/tmp/com.apple.launchd.3daKc8rqMY/Listeners', 'PERLBREW_ROOT': '/Users/fernandovidal/perl5/perlbrew', 'PATH': '/Users/fernandovidal/perl5/perlbrew/bin:/Users/fernandovidal/perl5/perlbrew/perls/perl-5.28.0/bin:/Users/fernandovidal/opt/anaconda3/bin:/Library/Frameworks/Python.framework/Versions/3.7/bin:/anaconda2/bin:/Library/Frameworks/Python.framework/Versions/3.7/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/Library/TeX/texbin:/usr/local/go/bin:/usr/local/share/dotnet:/opt/X11/bin:~/.dotnet/tools:/Library/Apple/usr/bin:/Library/Frameworks/Mono.framework/Versions/Current/Commands:/Applications/Xamarin Workbooks.app/Contents/SharedSupport/path-bin', 'LaunchInstanceID': 'E1BB0D00-50D1-4A62-B567-2114F7E29AC3', '__CFBundleIdentifier': 'com.apple.Terminal', 'PWD': '/Users/fernandovidal/Documents/Phd Coimbra/PublicacoesTrabalhar/SmartContract/smartcontract-faultinjector/solidity-ast/examples', 'LANG': 'pt_BR.UTF-8', 'PERLBREW_HOME': '/Users/fernandovidal/.perlbrew', 'XPC_FLAGS': '0x0', 'XPC_SERVICE_NAME': '0', 'SHLVL': '1', 'HOME': '/Users/fernandovidal', 'PERLBREW_MANPATH': '/Users/fernandovidal/perl5/perlbrew/perls/perl-5.28.0/man', 'PERLBREW_PATH': '/Users/fernandovidal/perl5/perlbrew/bin:/Users/fernandovidal/perl5/perlbrew/perls/perl-5.28.0/bin', 'PYTHONPATH': '/Library/Frameworks/Python.framework/Versions/3.7/lib/python3.7/site-packages:', 'LOGNAME': 'fernandovidal', 'DISPLAY': '/private/tmp/com.apple.launchd.PVZaPuo63Z/org.macosforge.xquartz:0', 'SECURITYSESSIONID': '186a8', '_': '/Library/Frameworks/Python.framework/Versions/3.7/bin/python3', '__CF_USER_TEXT_ENCODING': '0x1F5:0x0:0x47', '__PYVENV_LAUNCHER__': '/Library/Frameworks/Python.framework/Versions/3.7/bin/python3'}