#!/usr/bin/env python3
import sys
import os
import re

def main():
    print('contract_name;contract_classname;contract_id;reference_contract;odc_fault_id;odc_fault_variant')
    id = 0
    refcontracts = {}
    for filename in sorted(os.listdir(sys.argv[1])):
        if re.search("^.*-\\d+-\\d+\\.sol$", filename) is not None:
            tokens = filename.split('-')
            if '-0-0' in filename:
                refcontracts[tokens[0]] = id
            print('%s;%s;%s;%s;%s;%s' % (filename.replace('.sol', ''), tokens[0], id, refcontracts[tokens[0]], tokens[1], tokens[2].replace('.sol', '')))
            id += 1

if __name__ == "__main__":
    main()