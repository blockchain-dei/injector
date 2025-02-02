#!/usr/bin/env python3

from warnings import catch_warnings
from serializer import readastcompact
from common import getparent
import argparse
import random
import string
import os

p_randomints = 10
p_randomstrings = 5
p_stringlen = 10
p_addresses = 4

main_contract = ""
constr_args = []

# Generate a random string with given length
def randomstr(len):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters.strip()) for i in range(len))

# Get all literals from the subtree of a node
def getliterals(node):
    lits = []
    if node['name'] == 'Literal': lits.append(node)

    if 'children' in node:
        for c in node['children']:
            lits += getliterals(c)

    return lits

# Get possible input values for a given type of parameter for a given function
def geninputs(fnode, ptype, literals):
    # Elementary types
    if ptype['name'] == 'ElementaryTypeName':
        type = ptype['attributes']['type']
        if not type:
            return []
        # Integers (signed/unsigned)
        if type.startswith('int') or type.startswith('uint'):
            signed = type.startswith('i')
            bits = int(type.split('t')[1])
            smallest = -2**(bits-1) if signed else 0
            largest = 2**(bits-1)-1 if signed else 2**bits-1
            # Smallest, largest and 0
            candidates = [smallest, largest, 0]
            # Random
            for i in range(p_randomints):
                candidates.append(random.randint(smallest, largest))
            # Literals and +- 1
            for l in literals:
                try:
                    if l['attributes']['type'].startswith('int_const'):
                        val = int(l['attributes']['value'], 0)
                        candidates += [val, val+1, val-1]
                except:
                    continue

            # Filter duplicates and check range
            return list(set(['\'%d\'' % c for c in candidates if smallest <= c and c <= largest]))
        # Addresses
        if type in ['address', 'address payable']:
            return ['a[%d]' % s for s in getaddresses(fnode)]
        # Strings
        if type.startswith('string'): #type == 'string':
            # Empty string
            candidates = ['""']
            # Literals
            for l in literals:
                if l['attributes']['type'].startswith('literal_string'):
                    candidates.append('"%s"' % l['attributes']['value'].strip())
            # Random
            for i in range(p_randomstrings):
                candidates.append('"%s"' % randomstr(p_stringlen))
            # Filter duplicates
            return list(set(candidates))
        if type == 'bool':
            return ['true', 'false']
    if ptype['name'] == 'ArrayTypeName':
        # Empty
        arrs = ['[]']
        # Generate recursively, shuffle randomly and take some elements
        arr = geninputs(fnode, ptype['children'][0], literals)
        for l in [1, 2, 4, 8]:
            random.shuffle(arr)
            arrs.append('[%s]' % ', '.join(arr[0:l]))
        return arrs

    print('Warning: unsupported type ' + ptype['attributes']['type'])
    return []
"""        # CAMBIATO ho aggiunto questi ultimi due if, questo andrebbe prima di if type == 'bool'
        if type == 'bytes':
            # Genera array vuoti e casuali di lunghezza fissa
            candidates = ['""']  # Array vuoto
            for i in range(p_randomstrings):
                candidates.append('"%s"' % ''.join(random.choice(string.hexdigits) for _ in range(p_stringlen)))
            return list(set(candidates))
        if type.startswith('bytes') and len(type) > 5:
            try:
                length = int(type[5:])  # Esempio: "bytes32" -> lunghezza 32
                candidates = ['"%s"' % ''.join(random.choice(string.hexdigits) for _ in range(length))]
                return candidates
            except:
                pass
"""


    # Arrays


# Get possible msg.values
def getmsgvalues(node):
    return [0, 100, 10000, 1000000]

# Get possible adddresses
def getaddresses(node):
    return range(p_addresses)

# Generate tests for each function
def generate(root, node):
    global constr_args
    global main_contract
    result = []
    vVisibility = False;
    try:
       if node['attributes']['visibility']=='internal':
           vVisibility = True;
    except:
        vVisibility = False;

    try:
        if (node['name'] == 'FunctionDefinition') and (vVisibility == False):
            parent = getparent(root, node)
            # Skip libraries/interfaces
            if parent['name'] == 'ContractDefinition':# and parent['attributes']['contractKind'] == 'contract':
                try:
                    fname = '[constructor]' if node['attributes']['isConstructor'] else node['attributes']['name']
                except:
                    fname  = node['attributes']['name']
                hasstatemutabiltiy = 'stateMutability' in node['attributes']
                ispayable = hasstatemutabiltiy and 'payable' in node['attributes']['stateMutability']
                iscall = hasstatemutabiltiy and node['attributes']['stateMutability'] in ['pure', 'view']
                
                try:
                    if node['attributes']['isConstructor']:
                        if parent['attributes']['name'] == main_contract:
                            literals = getliterals(node)
                            for par in node['children'][0]['children']:
                                inputs = list(geninputs(node, par['children'][0], literals))
                                if len(inputs) > 0:
                                    constr_args.append(inputs[0])
                        return []
                except:
                    args = []

                # Generate a list of values for each parameter (incl. sender and value)
                args = []
                # msg.sender
                args.append(getaddresses(node))
                # msg.value (if payable)
                parstart = 1
                if hasstatemutabiltiy and ispayable:
                    args.append(getmsgvalues(node))
                    parstart = 2
                # Regular parameters
                literals = getliterals(node)
                for par in node['children'][0]['children']:
                    args.append(list(geninputs(node, par['children'][0], literals)))
                
                # Generate all combinations
                testcases = [[]]
                for i in range(len(args)):
                    next = []
                    for tc in testcases:
                        for a in args[i]:
                            tcnext = list(tc)
                            tcnext.append(a)
                            next.append(tcnext)
                            if next.__len__() > 10000:
                                break
                    testcases = next
                
                for tc in testcases:
                    result.append({
                        'type' : 'q' if iscall else 't',
                        'invoker' : 'c[%s]' % tc[0],
                        'function' : fname,
                        'args' : '[%s]' % ', '.join(tc[parstart:]),
                        'payable' : hasstatemutabiltiy and ispayable,
                        'weiValue' : str(tc[1]) if (hasstatemutabiltiy and ispayable) else ''
                    })

        # Recurse
        elif 'children' in node:
            for c in node['children']:
                result += generate(root, c)
    except:
        return result
    return result


def main():
    global constr_args
    global main_contract
    parser = argparse.ArgumentParser(description='Generate tests for a contract.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('input', type=str, help='Path to the input Solidity (.sol) or AST (.json) file')
    parser.add_argument('--limit', type=int, help='Limit the number of testcases')
    args = parser.parse_args()
    main_contract = os.path.splitext(os.path.basename(args.input))[0]
    result = readastcompact(args.input)
    ast = result['ast']
    with open(args.input.replace('.sol', '') + '.js', 'w') as f:
        f.write('\'use strict\';\n')
        f.write('function buildWorkload(c, a, evmContracts) {\n')
        f.write('\treturn [\n')
        testcases = generate(ast, ast)
        
        random.shuffle(testcases)
        if args.limit:
           testcases = testcases[:args.limit]
        testcases = testcases[:1500]
       
        for tc in testcases:
            f.write('\t\t{type: \'%s\', invoker: %s, function: \'%s\', args: %s%s},\n' % \
                (tc['type'], tc['invoker'], tc['function'], tc['args'], ', weiValue: %s' % tc['weiValue'] if tc['payable'] else ''))
        f.write('\t];\n')
        f.write('}\n')
        for i in range(len(constr_args)):
            if (constr_args[i].startswith('a[')):
                constr_args[i] = constr_args[i].replace('a[', '\'$USER_').replace(']', '\'')
        if len(constr_args) > 0:
            f.write('module.exports.ctrInit = [' + ','.join([str(a) for a in constr_args]) + '];\n')
        f.write('module.exports.buildWorkload = buildWorkload;\n')
        f.write('module.exports.workloadLength = %d;\n' % len(testcases))


if __name__ == "__main__":
    main()