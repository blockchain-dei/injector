#!/usr/bin/env python3

from common import mainfunc
import subprocess

'''
Vulnerability: 5.8.2 Outdated Compiler Version source: https://openscv.dei.uc.pt/

condition function task: identify the solc version.

action function task: switch to the latest version and re-compile the contract.

assumptions: version is >= x.y.z, once the version is found then switch to latoldestest version of solc.
'''

def condition(ast):
    _ast = []

    if ast.get("nodeType") == "SourceUnit" and ast.get("nodes", []):
        node = ast.get("nodes")[0]
        literals = node.get("literals", [])

        if node.get("nodeType") == "PragmaDirective":

            # Versione da confrontare (0.4.0)
            version_to_compare = [0, 5, 0]
            
            if literals[1] == "^" or literals[1] == ">=":
                # Estrai la versione (senza ^) e convertila in una lista di interi
                version_str = literals[2]
                version_parts = [int(part) for part in version_str.split('.')]
                
                # Confronta la versione estratta con quella di riferimento
                if version_parts[0] > version_to_compare[0]:
                    _ast.append(node)
                elif version_parts[0] == version_to_compare[0]:
                    if version_parts[1] > version_to_compare[1]:
                        _ast.append(node)
                    elif version_parts[1] == version_to_compare[1]:
                        Napoli = int(literals[3].lstrip('.'))
                        if Napoli > version_to_compare[2]:
                            _ast.append(node)

            else:
                # Se non c'è il "^", la versione è direttamente in literals[1]
                version_str = literals[1]
                version_parts = [int(part) for part in version_str.split('.')]
                
                # Confronta la versione estratta con quella di riferimento
                if version_parts[0] > version_to_compare[0]:
                    _ast.append(node)
                elif version_parts[0] == version_to_compare[0]:
                    if version_parts[1] > version_to_compare[1]:
                        _ast.append(node)
                    elif version_parts[1] == version_to_compare[1]:
                        Napoli = int(literals[2].lstrip('.'))
                        if Napoli > version_to_compare[2]:
                            _ast.append(node)

    return _ast


def action(ast, target_node):
    operation_type = None
    literals = target_node.get("literals")

    # Modifica la versione nel target_node
    if literals[1] == "^":
        target_node['literals'][2] = "0.5"
        target_node['literals'][3] = ".0"
    elif literals[1] == ">=":
        target_node['literals'][2] = "0.5"
        target_node['literals'][3] = ".0"
        target_node['literals'][4] = ""
        target_node['literals'][5] = ""
        target_node['literals'][6] = ""
    else:
        target_node['literals'][1] = "0.5"
        target_node['literals'][2] = ".0"

    target_node['literals'] = literals

    subprocess.call("solc-select use 0.5.0", shell=True)

    return target_node, operation_type


if __name__ == "__main__":
    mainfunc('5-8-2', condition, action, '5-8-2')
