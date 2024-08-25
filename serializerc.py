#!/usr/bin/env python3

import argparse
import json
import subprocess
import os
from ntpath import basename
import re


# Types
def typeNameToStr(node):
    if node['name'] == 'ElementaryTypeName':
        mutability = ''
        if 'stateMutability' in node['attributes'] and node['attributes']['stateMutability'] != 'nonpayable':
            mutability = ' ' + node['attributes']['stateMutability']
        return node['attributes']['name'] + mutability

    if node['name'] == 'UserDefinedTypeName':
        return node['attributes']['name']

    if node['name'] == 'Mapping':
        return 'mapping(%s => %s)' % (typeNameToStr(node['children'][0]), typeNameToStr(node['children'][1]))

    if node['name'] == 'ArrayTypeName':
        size = exprToStr(node['children'][1]) if len(node['children']) >= 2 else ''
        return typeNameToStr(node['children'][0]) + '[' + size + ']'

    if node['name'] == 'FunctionTypeName':
        params = paramListToStr(node['children'][0])
        visibility = ' ' + node['attributes']['visibility'] if 'visibility' in node['attributes'] else ''
        mutability = ''
        if 'stateMutability' in node['attributes'] and node['attributes']['stateMutability'] != 'nonpayable':
            mutability = ' ' + node['attributes']['stateMutability']
        returns = ''
        if len(node['children'][1]['children']) > 0:
            returns = ' returns %s' % paramListToStr(node['children'][1])
        return 'function%s%s%s%s' % (params, visibility, mutability, returns)

    raise TypeError('Unknown type: ' + node['name'])


# VariableDeclaration
def varToStr(node):
    v = typeNameToStr(node['children'][0]) if len(node['children']) > 0 else 'var'
    if 'storageLocation' in node['attributes'] and node['attributes']['storageLocation'] != 'default':
        v += ' ' + node['attributes']['storageLocation']
    if 'indexed' in node['attributes'] and node['attributes']['indexed']:
        v += ' indexed'
    if node['attributes']['name'] != '':
        v += ' ' + node['attributes']['name']
    return v


# ParameterList
def paramListToStr(node):
    return '(%s)' % ', '.join([varToStr(v) for v in node['children']])


# Expressions
def exprToStr(node):
    nName = node['name']
    nAttrs = node['attributes'] if 'attributes' in node else None
    nChildren = node['children'] if 'children' in node else None

    if nName == 'Conditional':
        return '(%s ? %s : %s)' % (exprToStr(nChildren[0]), exprToStr(nChildren[1]), exprToStr(nChildren[2]))

    if nName == 'Assignment':
        return '%s %s %s' % (exprToStr(nChildren[0]), nAttrs['operator'], exprToStr(nChildren[1]))

    if nName == 'TupleExpression':
        if nAttrs['isInlineArray']:
            return '[' + ', '.join(exprToStr(c) for c in nChildren) + ']'
        elif 'components' in nAttrs:  # Tuples on LHS have components
            return '(%s)' % ', '.join([(exprToStr(c) if c is not None else '') for c in nAttrs['components']])
        else:  # Tuples on RHS have children
            if nAttrs['type'].startswith('tuple('):  # Handle empty args based on type
                args = []
                i = 0
                for a in nAttrs['type'].replace('tuple(', '')[:-1].split(','):
                    if a != '':
                        if i < len(nChildren):
                            args.append(exprToStr(nChildren[i]))
                        i += 1
                    else:
                        args.append('')
                return '(%s)' % ', '.join(args)
            else:  # If the type is not tuple(...) just go through children
                return '(%s)' % ', '.join([(exprToStr(c) if c is not None else '') for c in nChildren])

    if nName == 'UnaryOperation':
        operand = exprToStr(nChildren[0])
        op = nAttrs['operator']
        if op == 'delete': return 'delete %s' % operand
        if nAttrs['prefix']:
            return '(%s%s)' % (op, operand)
        else:
            return '(%s%s)' % (operand, op)

    if nName == 'BinaryOperation':
        return '(%s %s %s)' % (exprToStr(nChildren[0]), nAttrs['operator'], exprToStr(nChildren[1]))

    if nName == 'FunctionCall':
        if ('names' in nAttrs and nAttrs['names'] is not None and len(nAttrs['names']) > 0 and nAttrs['names'][
            0] is not None):
            args = '{%s}' % ', '.join(
                [nAttrs['names'][i - 1] + ': ' + exprToStr(nChildren[i]) for i in range(1, len(nChildren))])
        else:
            args = ', '.join([exprToStr(c) for c in nChildren[1:]])
        return '%s(%s)' % (exprToStr(nChildren[0]), args)

    if nName == 'NewExpression':
        return 'new %s' % typeNameToStr(nChildren[0])

    if nName == 'MemberAccess':
        return '%s.%s' % (exprToStr(nChildren[0]), nAttrs['member_name'])

    if nName == 'IndexAccess':
        return '%s[%s]' % (exprToStr(nChildren[0]), exprToStr(nChildren[1]))

    if nName == 'Identifier':
        return nAttrs['value']

    if nName == 'ElementaryTypeNameExpression':
        if nChildren != None:
            return nChildren[0]['attributes']['name']
        else:
            return nAttrs['value']

    if nName == 'Literal':
        v = nAttrs['value']
        if nAttrs['type'] is not None and nAttrs['type'].startswith('literal_string'):
            return repr(v)
        if nAttrs['type'] == 'bool':
            return 'true' if v == 'true' else 'false'
        if nAttrs['subdenomination'] is not None:
            v += ' ' + nAttrs['subdenomination']
        return v

    if nName == 'VariableDeclaration':
        v = nAttrs['value']
        #print(typeNameToStr(nChildren[0]))
        # file.write(ind + typeNameToStr(nChildren[0]))
        # if nAttrs['stateVariable']: file.write(' ' + nAttrs['visibility'])
        # if nAttrs['constant']: file.write(' constant')
        # file.write(' ' + nAttrs['name'])
        # if len(nChildren) >= 2:
        #     file.write(' = ' + exprToStr(nChildren[1]))
        # if nl: file.write(';\n\n')
        return v
    raise TypeError('Unknown kind of expression: ' + nName)


def getContractSourceCode(contract):
    with open(contract) as f:
        contents = f.readlines()
        print(f"getContractSourceCode-contents: {contents}\n")
        return contents
    #with open(file_path, 'r') as file:
    #       source_code_lines = file.readlines()
    #  return source_code_lines
    return


def getContractSolVersion(contract):
    remove_words = ['pragma', 'solidity', '^', '>', '=', ';', '\n']
    #remove_words = ['pragma', 'solidity', '^', '>', '=', '<', ';','\n']    
    #print(f"getContractSolVersion-contract: {contract}\n")
    #contract = "contracts/" + contract
    #print(f"getContractSolVersion-contract2: {contract}\n")
    with open(contract) as f:
        contents = f.readlines()
        #print(f"getContractSolVersion-contents: {contents}\n")
        r = re.compile(".*pragma")
        versionlist = list(filter(r.match, contents))
        #print(f"getContractSolVersion-versionlist: {versionlist}\n")
        if len(versionlist) > 0:
            version = versionlist[0]
            #print(f"getContractSolVersion-version: {version}\n")
            for word in remove_words:
                version = version.replace(word, "")
            print(f"getContractSolVersion-version: {version}\n")
            split_specifiers = version.split("<")
            min_version = split_specifiers[0]
            max_version = f"{split_specifiers[1]}" if len(split_specifiers) > 1 else ""
            #print(f"getContractSolVersion-min_version: {min_version}\n")
            #print(f"getContractSolVersion-max_version: {max_version}\n")
            version = min_version
            if ((version.split()[0] == '0.4.0') or (version.split()[0] == '0.4.10') or (
                    version.split()[0] == '0.4.11') or (version.split()[0] == '0.4.13') or (
                    version.split()[0] == '0.4.16') or (version.split()[0] == '0.4.17') or (
                    version.split()[0] == '0.4.18') or (version.split()[0] == '0.4.19') or (
                    version.split()[0] == '0.4.20') or (
                    version.split()[0] == '0.4.21' or (version.split()[0] == '0.4.22'))):
                print(f"getContractSolVersion-change version from {version} to 0.4.25\n")
                return '0.4.25'
            return version.split()[0]
    return


def tri_recursionali(data, dataOut):
    # Load the compact AST JSON
    dataOut['attributes'] = {}
    dataOut['children'] = []
    #print(f"tri_recursionali:dataout0 {dataOut}")
    for attr in data:
        #print(f"1: {attr}")
        if attr == "id":
            dataOut["id"] = data["id"]
        elif attr == "nodeType":
            dataOut["name"] = data["nodeType"]
        elif attr == "src":
            dataOut["src"] = data["src"]
        elif attr == "exportedSymbols":
            dataOut['attributes'][attr] = data[attr]
        elif isinstance(data[attr], list):
            #print(f"2:list {attr}")
            if not data[attr]:
                #print("2.3:list is empty")
                dataOut['attributes'][attr] = ['null']
            elif all(isinstance(item, dict) for item in data[attr]):
                #print("2.5:list item")
                #dataOut['children']=[]
                for item in data[attr]:
                    #print("3:list item")
                    if "nodeType" in item:
                        # dataOut['children']=[]
                        d = {}
                        tri_recursionali(item, d)
                        dataOut['children'].append(d)
                    #print(f"3.5:d {d}")
            else:
                dataOut['attributes'][attr] = data[attr]
        elif isinstance(data[attr], dict):
            if "nodeType" in data[attr]:
                e = {}
                tri_recursionali(data[attr], e)
                dataOut['children'].append(e)
        else:
            #print("else")
            dataOut['attributes'][attr] = data[attr]
    #print(f"tri_recursionali:dataout1 {dataOut}")
    return dataOut


def remove_empty_nodes(full_ast):
    #print(f"remove_empty_nodes:full_ast0 {full_ast}")
    keys_to_delete = []
    for attr in full_ast:
        if attr == 'attributes' or attr == 'children':
            print("1")
            if isinstance(full_ast[attr], list) or isinstance(full_ast[attr], dict):
                print("2")
                if not full_ast[attr]:
                    print("3")
                    keys_to_delete.append(attr)
    # Remove keys from the dictionary
    #print(f"remove_empty_nodes:keys_to_delete {keys_to_delete}")
    for key in keys_to_delete:
        del full_ast[key]
    #print(f"remove_empty_nodes:full_ast1 {full_ast}")
    return full_ast


def convert_inheritance_specifier(node, indent_level=0):
    # Assuming node is an InheritanceSpecifier
    #base_contract_name = convert_to_source(node.get('baseName'), 0)  # Get the name of the base contract

    # If there are constructor arguments, convert them too
    #arguments = node.get('arguments', [])
    #if arguments:
    # Convert each argument
    #converted_args = [convert_to_source(arg, indent_level) for arg in arguments]
    #args_str = ", ".join(converted_args)
    #return f"{base_contract_name}({args_str})"
    #else:
    #return base_contract_name
    base_contract = node.get('baseName')
    base_contract_name = base_contract.get('name')
    return base_contract_name


def convert_to_source(node, indent_level=0):
    #print(f"convert_to_source-node: {node['id']}\n")
    if isinstance(node, list):
        return ''.join([convert_to_source(sub_node, indent_level) for sub_node in node])

    if node is None or not isinstance(node, dict):
        return ""

    indent = '    ' * indent_level
    node_type = node.get('nodeType')

    if node_type == 'SourceUnit':
        return '\n'.join(convert_to_source(child, indent_level) for child in node.get('nodes', []))

    elif node_type == 'PragmaDirective':
        literals = ''.join(node['literals'])
        # Check if it starts with 'solidity' and format accordingly
        if literals.startswith('solidity'):
            parts = literals.split("solidity", 1)
            if len(parts) == 2:
                before_solidity = parts[0].strip()
                after_solidity = parts[1].strip()
                #print(f"convert_to_source-node-PragmaDirective-after_solidity: {after_solidity}\n")
                split_specifiers = after_solidity.split("<")
                # Prepare the two independent statements
                first_statement = split_specifiers[0]
                second_statement = f"<{split_specifiers[1]}" if len(split_specifiers) > 1 else ""
                pragma_directive = f"pragma solidity{before_solidity} {first_statement} {second_statement};\n"
        elif 'experimental' in literals:
            # Special handling for 'experimental' to ensure spacing
            parts = literals.split('experimental')
            before_experimental = parts[0].strip()  # Should typically be empty
            after_experimental = parts[1].strip()
            pragma_directive = f"pragma experimental {after_experimental};\n"
        else:
            # Fallback for any other pragma types
            pragma_directive = f"pragma {literals};\n"
        return pragma_directive

    elif node_type == 'ContractDefinition':
        #"contractKind" : "contract",
        contract_kind = node.get('contractKind')
        contract_name = node.get('name')
        # Extracting base contracts (if any)
        base_contracts = node.get('baseContracts', [])
        inheritance_clause = ""
        if base_contracts:
            # Assuming base_contracts is a list of nodes where each node has the base contract's name accessible
            # The actual structure might differ based on your AST; adjust accordingly
            inherited_names = [convert_inheritance_specifier(base, indent_level) for base in base_contracts]
            # Joining the inherited contract names with ', ' and prepending ' is ' if there are any inheritance
            inheritance_clause = " is " + ", ".join(inherited_names)

        contract_body = '\n'.join(convert_to_source(child, indent_level + 1) for child in node.get('nodes', []))
        return f"{indent}{contract_kind} {contract_name}{inheritance_clause} {{\n{contract_body}\n{indent}}}\n"
        #return f"{indent}contract {contract_name} {{\n{contract_body}\n{indent}}}\n"

    # Function Definition
    elif node_type == 'FunctionDefinition':
        #print(f"convert_to_source-FunctionDefinition-node-id: {node['id']}\n")
        doc_string = checkfordoc(node, indent, indent_level)
        # Check if it's a constructor
        if node.get('kind') == 'fallback':
            parameters = ', '.join(
                convert_to_source(param, indent_level) for param in node.get('parameters', {}).get('parameters', []))
            body = convert_to_source(node.get('body', {}), indent_level)
            visibility = node.get('visibility', '')
            #visibility = node.get('visibility', 'public')
            state_mutability = node.get('stateMutability', '')
            state_mutability_str = f" {state_mutability}" if state_mutability and state_mutability != 'nonpayable' else ""
            # Handling modifiers if any
            modifiers_str = ''
            if 'modifiers' in node:
                for modifier in node['modifiers']:
                    mod_name = convert_to_source(modifier.get('modifierName'), 0)
                    if 'arguments' in modifier and modifier[
                        'arguments']:  # Check if there are arguments to the modifier
                        mod_args = ', '.join([convert_to_source(arg, 0) for arg in modifier['arguments']])
                        modifiers_str += f" {mod_name}({mod_args})"
                    else:
                        modifiers_str += f" {mod_name}"
            return f"{indent}fallback({parameters}) {visibility}{state_mutability_str}{modifiers_str}{body}{indent}"
        elif node.get('kind') == 'constructor' or node.get('isConstructor', False):
            parameters = ', '.join(
                convert_to_source(param, indent_level) for param in node.get('parameters', {}).get('parameters', []))
            body = convert_to_source(node.get('body', {}), indent_level)
            visibility = node.get('visibility', '')
            state_mutability = node.get('stateMutability', '')
            state_mutability_str = f" {state_mutability}" if state_mutability and state_mutability != 'nonpayable' else ""
            # Handling modifiers if any
            modifiers_str = convert_modifiers(node.get('modifiers', []), indent_level)
            #modifiers_str = ''
            #if 'modifiers' in node:
                #for modifier in node['modifiers']:
                    #mod_name = convert_to_source(modifier.get('modifierName'), 0)
                    #if 'arguments' in modifier and modifier[
                        #'arguments']:  # Check if there are arguments to the modifier
                        #mod_args = ', '.join([convert_to_source(arg, 0) for arg in modifier['arguments']])
                        #modifiers_str += f" {mod_name}({mod_args})"
                    #else:
                        #modifiers_str += f" {mod_name}"
            return f"{indent}constructor({parameters}) {visibility}{state_mutability_str}{modifiers_str}{body}{indent}"
        else:
            function_name = node.get('name', '')
            parameters = ', '.join(
                convert_to_source(param, 0) for param in node.get('parameters', {}).get('parameters', []))
            returnParameters222 = node.get('returnParameters', {})
            return_type = None
            if 'parameters' in returnParameters222 and returnParameters222['parameters'] is not None and len(
                    returnParameters222['parameters']) > 0:
                #returnParameters333 = returnParameters222.get('parameters', [])
                #return_type = convert_to_source(returnParameters333[0], 0)
                for returnparam in returnParameters222['parameters']:
                    #print(f"convert_to_source-FunctionDefinition-nodeid: {node['id']}\n")
                    #print(f"convert_to_source-FunctionDefinition-returnparam: {returnparam}\n")
                    if returnparam != None:
                        returnparamvalue = convert_to_source(returnparam, 0)
                        if return_type != None:
                            return_type += ','
                            return_type += f" {returnparamvalue}"
                        else:
                            return_type = f" {returnparamvalue}"
            body = ""
            if 'body' in node and node['body'] is not None:
                #if node['id'] == 102:
                    #print(f"convert_to_source-FunctionDefinition-body: {body}\n")
                body = convert_to_source(node.get('body', {}), indent_level)
                #if node['id'] == 102:
                    #print(f"convert_to_source-FunctionDefinition-body: {body}\n")
            visibility = node.get('visibility', '')
            #if visibility == 'public':
            #visibility = ''
            state_mutability = node.get('stateMutability', '')
            is_declared_const = node.get('isDeclaredConst', False)
            #state_mutability_str = f" {state_mutability}" if state_mutability and state_mutability != 'nonpayable' else ""
            if state_mutability == "pure" or state_mutability == "view":
                state_mutability_str = " " + state_mutability
            else:
                state_mutability_str = " constant" if is_declared_const else (
                    f" {state_mutability}" if state_mutability and state_mutability != 'nonpayable' else "")
            modifiers_str = convert_modifiers(node.get('modifiers', []), indent_level)
            #modifiers_str = ''
            #if 'modifiers' in node:
                #for modifier in node['modifiers']:
                    #mod_name = convert_to_source(modifier.get('modifierName'), 0)
                    #if 'arguments' in modifier and modifier[
                        #'arguments']:  # Check if there are arguments to the modifier
                        #mod_args = ', '.join([convert_to_source(arg, 0) for arg in modifier['arguments']])
                        #modifiers_str += f" {mod_name}({mod_args})"
                    #else:
                        #modifiers_str += f" {mod_name}"
            return_type_str = f" returns ({return_type})" if return_type else ""
            if 'body' in node and node['body'] is not None and body.strip():
                formatted_body = body
            else:
                formatted_body = " ;\n"
            function_signature = f"{indent}function {function_name}({parameters}) {visibility}{state_mutability_str}{modifiers_str}{return_type_str}{formatted_body}\n"
            return doc_string + function_signature

    elif node_type == 'ModifierDefinition':
        modifier_name = node.get('name', '')
        parameters = ', '.join(
            convert_to_source(param, indent_level) for param in node.get('parameters', {}).get('parameters', []))
        body = convert_to_source(node.get('body', {}), indent_level)

        return f"{indent}modifier {modifier_name}({parameters}) {body}{indent}\n"

    elif node_type == 'ModifierInvocation2':
        modifier_name = node.get('modifierName', {}).get('name', '')
        args = convert_arguments(node.get('arguments', []), indent_level)  # Assuming a function to convert arguments
        return f"{modifier_name}({args})"
    
    elif node_type == 'ModifierInvocation':
        modifier_name = node.get('modifierName', {}).get('name', '')
        #print(f"ModifierInvocation-node: {node}\n")
        if 'arguments' in node and node['arguments'] is not None:
            args = convert_arguments(node.get('arguments', []), indent_level)  # Assuming a function to convert arguments
        else:
            args = None
        # Only add parentheses if there are arguments
        modifier_invocation = f"{modifier_name}({args})" if args else f"{modifier_name}()"
        return modifier_invocation
        
    # Variable Declaration
    elif node_type == 'VariableDeclaration':
        #print(f"VariableDeclaration-node: {node}\n")
        if node.get('stateVariable', False):
            # Formatting state variables with correct indentation

            #if node['typeName']['nodeType'] == 'Mapping':
            #variable_type = get_map_variable_type(node)
            #else:
            #variable_type = get_variable_type(node)

            if 'typeName' in node and node['typeName'] is not None:
                variable_type = convert_type(node['typeName'])
            else:
                variable_type = "var"
            indexed = node.get('indexed', False)
            if "indexed" == True:
                variable_type += ' indexed'
            if 'typeName' in node and node['typeName'] is not None and 'stateMutability' in node['typeName'] and \
                    node['typeName']['stateMutability'] == 'payable':
                variable_type += " payable"
            variable_name = node.get('name')
            visibility = node.get('visibility', '')
            if 'visibility' in node:
                if 'visibility' == 'internal':
                    visibility = ' private'
                else:
                    visibility = node['visibility']
            #value = convert_to_source(node.get('value'), 0) if node.get('value') else ''
            #value_str = f" = {value}" if value else ''
            value = ''
            if 'value' in node and node['value'] is not None:
                #if node['value']['nodeType'] == 'Literal' and 'hexValue' in node['value']:
                value_node = node.get('value', {})
                value_node2 = ''
                if 'value' in value_node:
                    value_node2 = value_node.get('value', '')  #value_node["value"] #
                    value_content = value_node['value']
                #if node['name'] == "EIP191_HEADER":
                #print(f"VariableDeclaration-value_node: {value_node}\n")
                #print(f"VariableDeclaration-value_node2: {value_node2}\n")
                #print(f"VariableDeclaration-value_node3: {node.get('value', {}).get('value', '')}\n")
                #print(f"VariableDeclaration-value_content: {value_content}\n")
                if '\\u' in value_node2:
                    # Convert hexValue to a string literal with escape sequences
                    hex_value = node['value']['hexValue']
                    #print(f"VariableDeclaration-hex_value: {hex_value}\n")
                    # Split the hexValue into pairs and convert each to the corresponding escape sequence
                    value = ''.join([f"\\x{hex_value[i:i + 2]}" for i in range(0, len(hex_value), 2)])
                    value = f'"{value}"'  # Enclose the result in quotes to form a valid string literal
                else:
                    # Handle other types of values normally
                    value = node['value'].get('value', '')
                    value = convert_to_source(node.get('value'), 0) if node.get('value') else ''
            value_str = f" = {value}" if value else ''

            #value_node = node.get('value', {})
            #value_str = ''
            #if value_node:
            #if '\\u' in value_node.get('value', ''):
            # Convert each Unicode escape sequence into the corresponding character
            # This is simplified; for actual use, more complex decoding might be needed
            #decoded_string = value_node['value'].encode().decode('unicode_escape')
            # Convert to a hexadecimal representation for solidity
            #value_str = '"' + ''.join([f"\\x{hex(ord(c))[2:]}" for c in decoded_string]) + '"'
            #else:
            # Directly use the value for regular string literals
            #value_str = f" = {value_node.get('value', '')}"

            if node['constant']:
                return f"{indent}{variable_type} {visibility} constant {variable_name}{value_str};\n"
            else:
                return f"{indent}{variable_type} {visibility} {variable_name}{value_str};\n"

        else:
            #if node['id'] == 248:
            #print(f"VariableDeclaration-hello\n")
            #var_name = node.get('name', '')
            #return f"{var_type} {var_name}"
            # Handle local variables and function/event parameters
            #type_name = node['typeName']['name'] if 'name' in node['typeName'] else ''
            storage_location = node.get('storageLocation', '')
            if storage_location == "default":
                storage_location = ''
            #print(f"convert_to_source-VariableDeclaration-node-id: {node["id"]}\n")

            #old var_type
            #if 'typeName' in node and node['typeName'] is not None:
            #var_type = node.get('typeName', {}).get('name', 'var')
            #else:
            #var_type = "var"
            #if node['typeName'] is not None and node['typeName']['nodeType'] == 'ArrayTypeName':
            #base_type = node['typeName']['baseType']['name']
            #var_type = f"{base_type}[]"
            #if 'typeName' in node and node['typeName'] is not None and 'stateMutability' in node['typeName'] and node['typeName']['stateMutability'] == 'payable':
            #var_type += " payable"
            #old var_type

            if 'typeName' in node and node['typeName'] is not None:
                var_type = convert_type(node['typeName'])
            else:
                var_type = "var"
            indexed = node.get('indexed', False)
            if "indexed" == True:
                var_type += ' indexed'
            if 'typeName' in node and node['typeName'] is not None and 'stateMutability' in node['typeName'] and \
                    node['typeName']['stateMutability'] == 'payable':
                var_type += " payable"

            var_name = node.get('name', '')
            indexed = node.get('indexed', False)
            indexed_str = ' indexed' if indexed else ''
            visibility = False  #node.get('visibility', '').strip()
            visibility_str = f" {visibility}" if visibility else ''
            return f"{var_type}{indexed_str}{visibility_str} {storage_location} {var_name}"

    # Variable Declaration Statement
    elif node_type == 'VariableDeclarationStatement':
        is_tuple_assignment = len(node.get('declarations', [])) > 1 or None in node.get('declarations', [])
        #if node['id'] == 203:
            #print(f"VariableDeclarationStatement-is_tuple_assignment: {is_tuple_assignment}\n")
        declarations = ', '.join(convert_to_source(decl, 0) for decl in node.get('declarations', []))
        # Handling tuple assignment with empty slots
        if 'initialValue' in node and node.get('initialValue'):
            initialValue = convert_to_source(node.get('initialValue'), 0)
            if is_tuple_assignment:
                return f"{indent}({declarations}) = {initialValue};\n"
            else:
                return f"{indent}{declarations} = {initialValue};\n"
        else:
            return f"{indent}{declarations};\n"

   # Handle UncheckedBlock
    if node_type == 'UncheckedBlock':
        statements = node.get('statements', [])
        # Convert each statement within the unchecked block to source code
        converted_statements = [convert_to_source(statement, indent_level + 1) for statement in statements]
        # Join all converted statements, add proper indentation, and wrap within `unchecked { ... }`
        block_content = '\n'.join(converted_statements)
        #if node['id'] == 102:
            #print(f"UncheckedBlock-block_content: {block_content}\n")
        return f"{indent}unchecked {{\n{block_content}{indent}}}\n"

    # Expression Statement
    elif node_type == 'ExpressionStatement':
        doc_string = checkfordoc(node, indent, indent_level)
        expression = convert_to_source(node.get('expression'), 0)
        return doc_string + f"{indent}{expression};\n"

    elif node_type == 'UserDefinedTypeName':
        # This handles user-defined types, potentially prefixed with the contract name or namespace
        return node['name']

    elif node_type == 'ElementaryTypeName':
        # Directly return elementary types (e.g., uint256, address)
        return node['name']

    # Handle StructuredDocumentation
    elif node_type == 'StructuredDocumentation':
        text = node.get('text', '').strip()
        # Format the documentation with appropriate comment syntax
        # Splitting the text into lines for proper comment block formatting
        lines = text.split('\n')
        formatted_lines = [f"{indent} * {line}" for line in lines]
        comment_block = f"{indent}/**\n" + '\n'.join(formatted_lines) + f"\n{indent} */\n"
        return comment_block

    # Example handling for a Conditional node within convert_to_source function
    elif node_type == 'Conditional':
        condition = convert_to_source(node.get('condition'), 0).strip()
        true_expression = convert_to_source(node.get('trueExpression'), 0).strip()
        false_expression = convert_to_source(node.get('falseExpression'), 0).strip()
        return f"({condition}) ? {true_expression} : {false_expression}"

    elif node_type == 'NewExpression2':
        type_name = convert_to_source(node.get('typeName'), 0)
        args = ', '.join([convert_to_source(arg, 0) for arg in node.get('arguments', [])])
        return f"new {type_name}({args})"

    elif node_type == 'NewExpression':
        type_name_object = convert_to_source(node.get('typeName'), 0)
        type_name = node['typeName']['name']
        #print(f"convert_to_source-NewExpression-node-id: {node["id"]}\n")
        #print(f"convert_to_source-NewExpression-node: {node}\n")
        #print(f"convert_to_source-NewExpression-type_name: {type_name}\n")
        #print(f"convert_to_source-NewExpression-type_name: {node['typeName']['name']}\n")
        #print(f"convert_to_source-NewExpression-type_name: {type_name['name']}\n")
        # Some NewExpressions won't have arguments, like `new bytes(length)`
        # But we must ensure to capture those cases where there are arguments
        arguments = node.get('arguments', [])
        if arguments:  # If there are arguments, process them
            args_str = ', '.join([convert_to_source(arg, 0) for arg in arguments])
            return f"new {type_name}({args_str})"
        else:  # If no arguments, just provide the type name
            return f"new {type_name}"

    elif node_type == 'EnumDefinition':
        enum_name = node.get('name')
        members = node.get('members', [])
        member_names = [member['name'] for member in members]  # Extract names of enum members
        members_str = ',\n'.join(member_names)  # Create a comma-separated string of member names
        return f"{indent}enum {enum_name} {{\n{members_str}\n}}\n"  # Construct the enum definition string

    elif node_type == 'UsingForDirective':
        # Extracting the library name from the libraryName node
        library_name = node['libraryName']['name']

        # Extracting the type name for which the library is used
        type_name = node['typeName']['name']

        # Forming the using directive statement
        using_statement = f"using {library_name} for {type_name};\n"

        return f"{indent}{using_statement}"

    elif node_type == 'StructDefinition':
        struct_name = node.get('name', '')
        members = node.get('members', [])

        member_declarations = []
        for member in members:
            # Assuming there's a function to convert variable declarations which handles
            # visibility, type name, etc.
            #1member_declaration = convert_variable_declaration(member, indent_level + 1) + ';'
            member_declaration = f"{indent}{convert_to_source(member, indent_level + 1)}"
            member_declaration += ';'
            member_declarations.append(member_declaration)

        # Joining all member declarations with a newline for readability
        members_str = '\n'.join(member_declarations)

        struct_definition = f"{indent}struct {struct_name} {{\n{members_str}\n{indent}}}\n"
        return struct_definition

    elif node_type == 'InlineAssembly2':
        assembly_code = node.get('operations', '').strip()
        assembly_code = assembly_code.lstrip('{').rstrip('}')
        indent = '    ' * indent_level
        formatted_assembly_code = '\n'.join([indent + line for line in assembly_code.split('\n')])

        # Add extra indentation for the assembly block content
        assembly_block = f"{indent}assembly {{\n{formatted_assembly_code}\n{indent}}}\n"
        return assembly_block

    elif node_type == 'InlineAssembly':
        # Handle the case where the inline assembly code is provided as a string under 'operations'
        if 'operations' in node:
            assembly_code = node.get('operations', '').strip()
            assembly_code = assembly_code.lstrip('{').rstrip('}')
            # Split the assembly code into lines for proper indentation
            assembly_lines = assembly_code.split('\n')
            # Add extra indentation for each line of the assembly code
            indented_assembly_lines = [f"{indent}{line.strip()}" for line in assembly_lines]
            formatted_assembly_code = '\n'.join(indented_assembly_lines)

            # Wrap the indented assembly code within the `assembly { ... }` block
            #return f"{indent}assembly {{\n{formatted_assembly_code}\n{indent}}}\n"
            return f"{indent}assembly {{{formatted_assembly_code}}}\n"
        else:
            # Assuming 'YulBlock' directly under 'AST' for simplicity
            yul_block = node.get('AST', {}).get('statements', [])
            yul_code = '\n'.join([convert_to_source(stmt, indent_level + 1) for stmt in yul_block])
            return f"{indent}assembly {{\n{yul_code}\n{indent}}}\n"

    elif node_type == 'YulBlock':
        statements = node.get('statements', [])
        block_content = '\n'.join([convert_to_source(stmt, indent_level + 1) for stmt in statements])
        return f"{indent}{{\n{block_content}\n{indent}}}\n"

    elif node_type == 'YulVariableDeclaration':
        var_names = ', '.join([var['name'] for var in node.get('variables', [])])
        value = convert_to_source(node.get('value'), 0) if node.get('value') else ''
        return f"{indent}let {var_names} := {value}\n"

    elif node_type == 'YulAssignment':
        var_names = ', '.join([var['name'] for var in node.get('variableNames', [])])
        value = convert_to_source(node.get('value'), 0)
        return f"{indent}{var_names} := {value}\n"

    elif node_type == 'YulFunctionCall':
        function_name = node.get('functionName', {}).get('name', '')
        args = ', '.join([convert_to_source(arg, 0) for arg in node.get('arguments', [])])
        return f"{function_name}({args})"

    elif node_type == 'YulIdentifier':
        return node.get('name', '')

    elif node_type == 'YulLiteral':
        return node.get('value', '')
        
    elif node_type == 'PlaceholderStatement':
        return f"{indent}_;\n"

    elif node_type == 'Throw':
        # For older versions of Solidity, you might directly return "throw;"
        # However, using "revert();" is more compatible with modern Solidity
        #return f"{indent}revert();\n"
        return f"{indent}throw;\n"

    elif node_type == 'ForStatement':

        # Convert each part of the for-loop
        init_expr = convert_to_source(node.get('initializationExpression'), 0).strip()
        init_expr = init_expr.rstrip(';')
        condition_expr = convert_to_source(node.get('condition'), 0).strip()
        loop_expr = convert_to_source(node.get('loopExpression'), 0).strip()
        loop_expr = loop_expr.rstrip(';')
        body = convert_to_source(node.get('body'), indent_level + 1)
        body = body.lstrip('{').rstrip('}').strip()
        # Ensuring semicolon presence where necessary and avoiding extra spaces
        init_part = f"{init_expr};" if init_expr else ""
        condition_part = f"{condition_expr};" if condition_expr and loop_expr else condition_expr
        loop_part = loop_expr

        # Assembling the for-loop string with proper formatting
        for_loop_str = f"{indent}for ({init_part} {condition_part} {loop_part}) {body}\n"
        #for_loop_str = f"{indent}for ({init_part} {condition_part} {loop_part}) {{\n{body}\n{indent}}}"
        return for_loop_str

    # Return
    elif node_type == 'Return':
        return_expression = ''
        if 'expression' in node and node.get('expression'):
            return_expression = convert_to_source(node.get('expression'), 0)
        return f"{indent}return {return_expression};\n"

    elif node_type == 'IfStatement':
        condition = convert_to_source(node.get('condition'), 0)
        true_body = convert_to_source(node.get('trueBody'), indent_level + 1)
        false_body = convert_to_source(node.get('falseBody'), indent_level + 1) if node.get('falseBody') else ""

        # Check if true body is a block with multiple statements
        if 'statements' in node.get('trueBody', {}): #and len(node['trueBody']['statements']) > 1:
            true_block = f"\n{true_body}"
        else:
            # Remove leading and trailing whitespace and braces
            true_block = true_body.strip().rstrip('}').lstrip('{').strip()
            true_block = f" {true_block}\n" if true_block else "{}"

        # Generate if block
        if_block = f"{indent}if ({condition}){true_block}"

        # Check if false body has multiple lines (which implies multiple statements)
        if false_body.count('\n') > 1:
            else_block = f"{indent}else "
            else_block += f"\n{false_body}"
        elif false_body:
            # Remove leading and trailing whitespace and braces for single statement
            else_block = false_body.strip().rstrip('}').lstrip('{').strip()
            else_block = f"{indent}else {else_block}\n"
        else:
            else_block = ""

        return if_block + else_block

    # Event Definition
    elif node_type == 'EventDefinition':
        event_name = node.get('name')
        parameters = ', '.join(
            convert_to_source(param, 0) for param in node.get('parameters', {}).get('parameters', []))
        return f"{indent}event {event_name}({parameters});\n"

    # Assignment
    elif node_type == 'Assignment':
        left_side = convert_to_source(node.get('leftHandSide'), 0)
        #print(f"Assignment-left_side: {left_side}\n")
        right_side = convert_to_source(node.get('rightHandSide'), 0)
        #print(f"Assignment-right_side: {right_side}\n")
        operator = node.get('operator')
        return f"{left_side} {operator} {right_side}"

    # Block
    elif node_type == 'Block':
        statements = ''.join(convert_to_source(statement, indent_level + 1) for statement in node.get('statements', []))
        #if node['id'] == 102:
            #print(f"Block-statements: {statements}\n")
        return f"{indent}{{\n{statements}{indent}}}\n"

    # Index Access
    elif node_type == 'IndexAccess':
        base = convert_to_source(node['baseExpression'])
        index = convert_to_source(node['indexExpression'])
        return f"{base}[{index}]"

    # Conditional
    elif node_type == 'Conditional':
        condition = convert_to_source(node.get('condition'), 0)
        true_expr = convert_to_source(node.get('trueExpression'), 0)
        false_expr = convert_to_source(node.get('falseExpression'), 0)
        return f"{true_expr} if {condition} else {false_expr}"

    # Elementary Type Name Expression
    elif node_type == 'ElementaryTypeNameExpression':
        typeName = node['typeName']
        #print(f"convert_to_source-node-ElementaryTypeNameExpression: {typeName}\n")
        if 'name' in typeName and typeName['name'] is not None:
            typeName = node['typeName']['name']
        if typeName == 'address' and 'stateMutability' in typeName:
            stateMutability = node['typeName'].get('stateMutability')
            if stateMutability == 'payable':
                expr_to_convert = ""  # Placeholder for the actual expression conversion logic
                return f"payable"
        else:
            return typeName

    # Unary Operation
    elif node_type == 'UnaryOperation':
        operator = node.get('operator')
        prefix = node.get('prefix')
        sub_expression = convert_to_source(node.get('subExpression'), 0)
        if prefix:
            return f"{operator}{sub_expression}"
        else:
            return f"{sub_expression}{operator}"

    # Function Call
    elif node_type == 'FunctionCall':
        expression = node.get('expression', {})
        args = ', '.join(convert_to_source(arg, 0) for arg in node.get('arguments', []))

        # Check if it's a call on a MemberAccess (e.g., something.send())
        if expression.get('nodeType') == 'MemberAccess':
            member_name = expression.get('memberName')
            expr = convert_to_source(expression.get('expression'), 0)

            # Special handling for payable().send
            if member_name == 'send' and "payable" in expr:
                return f"{indent}{expr}.send({args})"
            else:
                return f"{indent}{expr}.{member_name}({args})"
        elif 'kind' in node and node['kind'] is not None and node['kind'] == 'typeConversion':
            argument_src = convert_to_source(node['arguments'][0])
            converted_type = convert_to_source(node['expression'])
            return f"{converted_type}({argument_src})"
        else:
            # Regular function call
            callee = convert_to_source(expression, 0)
            return f"{indent}{callee}({args})"

    # Member Access
    elif node_type == 'MemberAccess':
        expr = convert_to_source(node.get('expression'), 0)
        member_name = node.get('memberName')
        return f"{expr}.{member_name}"

    # assert
    elif node_type == 'assert':
        expression = convert_to_source(node.get('expression'), 0)
        return f"{indent}assert({expression});\n"

    # Emit Statement
    elif node_type == 'EmitStatement':
        event_call = convert_to_source(node.get('eventCall'), 0)
        return f"{indent}emit {event_call};\n"

    # Tuple Expression
    elif node_type == 'TupleExpression':
        if not node.get('isInlineArray', False):
        	components = ', '.join(convert_to_source(component, 0) for component in node.get('components', []))
        	return f"({components})"
        # Check if this tuple expression is used as an array initialization
        else:
        	if 'components' in node:
        		components = [convert_to_source(comp, 0) for comp in node.get('components', [])]
        		if all(comp['nodeType'] == 'Literal' for comp in node.get('components', [])):
        			return f"[{', '.join(components)}]"
        		else:
        			return f"({', '.join(components)})"

    # Identifier
    elif node_type == 'Identifier':
        name = node.get('name', '')
        return name

    # Literal
    elif node_type == 'Literal':
        #print(f"Literal-node: {node}\n")
        #if node['id'] == 1508 or node['id'] == 1602:
        if 'kind' in node and node['kind'] == 'bool':
            value = node.get('value')
        elif 'typeDescriptions' in node and node['typeDescriptions']['typeString'] == 'bool':
            value = node.get('value')
        else:
            value = extract_and_escape_string(node['hexValue'])
        #print(f"Literal-hexstring: {hexstring}\n")
        #value = node.get('value')
        # Handling different kinds of literals (e.g., string, number) might require additional formatting
        kind = node.get('kind')
        if kind == 'string':
            return f'"{value}"'
        elif 'subdenomination' in node and node.get('subdenomination'):
            return f"{value} {node.get('subdenomination')}"
        return str(value)

    # Binary Operation
    elif node_type == 'BinaryOperation':
        left_expression = convert_to_source(node.get('leftExpression'), 0)
        right_expression = convert_to_source(node.get('rightExpression'), 0)
        operator = node.get('operator')
        return f"({left_expression} {operator} {right_expression})"

    return ""


def extract_and_escape_string(hex_value):
    # Decode the hex value to bytes
    decoded_bytes = bytes.fromhex(hex_value)
    # Prepare an output string, escaping non-printable characters
    escaped_string = ''.join(f'\\x{b:02x}' if b < 32 or b > 126 else chr(b) for b in decoded_bytes)
    return escaped_string

def convert_modifiers(modifiers, indent_level):
    if not modifiers:
        return ""
    return " " + " ".join([convert_to_source(mod, indent_level) for mod in modifiers])

def convert_arguments(arguments, indent_level):
    return ', '.join([convert_to_source(arg, indent_level) for arg in arguments])

def convert_arguments2(arguments, indent_level):
    # Assuming each argument is either a simple type or needs further processing
    #print(f"convert_arguments-arguments: {arguments}\n")
    #return " " + " ".join([convert_to_source(mod, indent_level) for mod in modifiers])
    #return ', '.join([convert_to_source(arg, indent_level) for arg in arguments])  # Simplified for example
    # Create a list to hold the converted arguments
    converted_args = []
    for arg in arguments:
        if arg['nodeType'] == 'Identifier':
            converted_args.append(arg.get('name', ''))
        elif arg['nodeType'] == 'Literal':
            # Determine how to handle based on the kind of literal
            if arg.get('kind') == 'bool':
                # Boolean literals: directly use the 'value' which should be 'true' or 'false'
                converted_args.append(arg.get('value', ''))
            else:
                # For other types of literals, directly use the value
                value = arg.get('value', '')
                # Optionally handle hex values if they are expected to be other types
                if arg.get('hexValue'):
                    try:
                        # If the hex value needs to be interpreted as an integer
                        value = str(int(arg.get('hexValue', ''), 16))
                    except ValueError:
                        # In case of a failure in interpretation, fall back to the raw value
                        value = arg.get('value', '')
                converted_args.append(value)

    return ', '.join(converted_args)
    
def convert_type(node):
    #if variable['id'] == 11:
    #print(f"variabledeclaration-convert_type-variable: {variable}\n")
    #if 'typeName' in variable and variable['typeName'] is not None:
    #node = variable['typeName']
    #print(f"variabledeclaration-convert_type-node: {node}\n")
    if node['nodeType'] == 'Mapping':
        #print(f"variabledeclaration-convert_type-1\n")
        return convert_mapping(node)
    #print(f"variabledeclaration-convert_type-var_type: {var_type}\n")
    elif node['nodeType'] == 'UserDefinedTypeName':
        #print(f"variabledeclaration-convert_type-2\n")
        #print(f"variabledeclaration-convert_type-node: {node}\n")
        if 'pathNode' in node and node['pathNode'] is not None:
            return node['pathNode']['name']
        else:
            return node['name']
    elif node['nodeType'] == 'ElementaryTypeName':
        #print(f"variabledeclaration-convert_type-3\n")
        return node['name']
    elif node['nodeType'] == 'ArrayTypeName':
        #print(f"variabledeclaration-convert_type-4\n")
        base_type = node['baseType']['name']
        return f"{base_type}[]"
    else:
        #print(f"variabledeclaration-convert_type-5\n")
        return node.get('typeName', {}).get('name', 'var')
    #print(f"variabledeclaration-convert_type-7\n")
    #return var_type


def convert_mapping(node):
    #print(f"variabledeclaration-convert_type-11\n")
    if node['nodeType'] == 'Mapping':
        #print(f"variabledeclaration-convert_type-12\n")
        key_type = convert_type(node['keyType'])
        value_type = convert_type(node['valueType'])
        return f"mapping({key_type} => {value_type})"
    elif node['nodeType'] == 'UserDefinedTypeName':
        return node['name']
    elif node['nodeType'] == 'ElementaryTypeName':
        return node['name']
    else:
        # Extend this for other types as necessary
        #print(f"variabledeclaration-convert_type-13\n")
        return ""


# Helper function to handle VariableDeclaration nodes
def convert_variable_declaration(node, indent_level=0):
    indent = '    ' * indent_level
    var_type = node.get('typeName', {}).get('name', '')
    var_name = node.get('name', '')
    return f"{indent}{var_type} {var_name}"
    # Additional node types handling with the correct indentation


def get_variable_type(variable):
    #print(f"\n get_variable_type: {variable['id']}\n")
    if 'typeName' in variable and variable['typeName'] is not None:
        var_type = variable.get('typeName', {}).get('name', 'var')
    else:
        var_type = "var"
    if variable['typeName'] is not None and variable['typeName']['nodeType'] == 'ArrayTypeName':
        base_type = variable['typeName']['baseType']['name']
        var_type = f"{base_type}[]"
    indexed = variable.get('indexed', False)
    if "indexed" == True:
        var_type += ' indexed'
    return var_type


def get_map_variable_type(variable):
    #event_type = variable['typeName']['keyType']['name']
    #event_type = variable['typeDescriptions']['typeString']
    #return event_type
    key_type = convert_to_source(variable['typeName']['keyType'], 0)
    value_type = convert_to_source(variable['typeName']['valueType'], 0)
    type_name = f"mapping({key_type} => {value_type})"
    #if variable['id'] == 11:
    #print(f"get_map_variable_type-key_type: {key_type}\n")
    #print(f"get_map_variable_type-value_type: {value_type}\n")
    #print(f"get_map_variable_type-type_name: {type_name}\n")
    return type_name

def checkfordoc(node, indent, indent_level):
    doc_string = ''
    if 'documentation' in node and node['documentation'] is not None:
        doc_node = node['documentation']
        #print(f"convert_to_source-FunctionDefinition-doc-0\n")
        if isinstance(doc_node, str):  # Unstructured documentation is just a plain string
            # Format the string as a comment block
            #print(f"convert_to_source-FunctionDefinition-doc-1\n")
            doc_lines = doc_node.strip().split('\n')
            formatted_doc_lines = [f"{indent}// {line.strip()}" for line in doc_lines]
            doc_string += '\n'.join(formatted_doc_lines) + '\n'
            #print(f"convert_to_source-FunctionDefinition-doc_string1: {doc_string}\n")
        elif isinstance(doc_node, dict) and doc_node['nodeType'] == 'StructuredDocumentation':
            #print(f"convert_to_source-FunctionDefinition-doc-2\n")
            doc_string = convert_to_source(doc_node, indent_level)
            #print(f"convert_to_source-FunctionDefinition-doc_string2: {doc_string}\n")
        elif 'nodeType' in doc_node and doc_node['nodeType'] is not None and doc_node['nodeType'] == 'StructuredDocumentation':
            #print(f"convert_to_source-FunctionDefinition-doc-3\n")
            doc_string = convert_to_source(doc_node, indent_level)
            #print(f"convert_to_source-FunctionDefinition-doc_string3: {doc_string}\n")
        else:
            #print(f"convert_to_source-FunctionDefinition-doc-4\n")
            doc_lines = doc_node.strip().split('\n')
            formatted_doc_lines = [f"{indent}// {line.strip()}" for line in doc_lines]
            doc_string += '\n'.join(formatted_doc_lines) + '\n'
            #print(f"convert_to_source-FunctionDefinition-doc_string4: {doc_string}\n")
    return doc_string
        
def convert_ast_source(ast):
    return convert_to_source(ast)


def writeastcompact(outfile, output_structure):
    with open(outfile, 'w') as file:
        # Serialize the output_structure to a JSON-formatted str and write it to the file
        json.dump(output_structure, file, indent=2)


def writesourcecode(outfile, output_structure):
    #dataOut={}
    #output_structure = convert_to_source(ast)
    #111print(f"output_structure:\n {output_structure}")
    #output_file_path = f"backsol-{input_file_path}.sol"
    with open(outfile, 'w') as file:
        file.write(output_structure)


#print(f"Solidity code saved to: {outfile}")

def writeastcompactold(ast, outfile):
    #dataOut={}
    output_structure = convert_to_source(ast)
    #111print(f"output_structure:\n {output_structure}")
    #output_file_path = f"backsol-{input_file_path}.sol"
    with open(outfile, 'w') as file:
        file.write(output_structure)


#print(f"Solidity code saved to: {outfile}")

# Reads a Solidity AST in .json or .sol format (first argument)
# and serializes it back into .sol source code (second argument).
def readastcompact(infile):
    # Call the compiler first for sol files
    #print(f"readastcompact-infile: {infile}\n")
    ast = ""
    #print(f"readastcompact-1\n")
    if infile.endswith('.sol'):
        #print(f"readastcompact-2\n")
        version = getContractSolVersion(infile)
        #print(f"readastcompact-3\n")
        #if ((version.split()[0] ==  '0.4.16') or (version.split()[0] ==  '0.4.17')   or (version.split()[0] ==  '0.4.18')  or (version.split()[0] ==  '0.4.19')  or  (version.split()[0] ==  '0.4.20') or  (version.split()[0] ==  '0.4.21' or  (version.split()[0] ==  '0.4.22'))   ):
        #print(f"readastcompact-Comiler version: not supported: {version}\n")
        #return { "ast": "", "version": version }
        if version:
            subprocess.call("solc-select use " + version, shell=True)
            #compiler_version_use_res = subprocess.run(['solc-select', 'use', 'always_install', version], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            #print(f"readastcompact-compiler_version_use_res:{compiler_version_use_res}\n")
        #print(f"readastcompact-4\n")
        result = subprocess.run(['solc', '--ast-compact-json', '--overwrite', '--output-dir', './', infile],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        #print(f"readastcompact-5\n")
        #print(f"readastcompact-result:{result}\n")
        # Decode stderr to a string for easier processing
        #print(f"readastcompact-result.returncode:{result.returncode}\n")
        #stderr_output = result.stderr.decode()
        #print(f"readastcompact-stderr_output:{stderr_output}\n")
        # Check for errors and warnings
        if result.returncode == 0:  #and not stderr_output:
            print(f"readastcompact-converting-src-to-ast-compilation successful without any errors.\n")
            tmpjsonfile = basename(infile + '_json.ast')
            #print(f"readastcompact-tmpjsonfile: {tmpjsonfile}\n")
            with open(tmpjsonfile) as f:
                ast = json.load(f)
            os.remove(tmpjsonfile)
        #os.remove(tmpjsonfile)
        #elif result.returncode != 0 and "Error:" in stderr_output:
        #print(f"Compilation failed with errors and possibly warnings.\n")
        #elif result.returncode != 0 and "Warning:" in stderr_output and "Error:" not in stderr_output:
        #print(f"Compilation finished with warnings but no errors..\n")
        else:
            print(f"readastcompact-converting-src-to-ast-error: Unexpected case or output.\n")

            #if result.returncode == 0:
        #tmpjsonfile = basename(infile + '_json.ast')
        #print(f"readastcompact-tmpjsonfile: {tmpjsonfile}\n")
        #with open(tmpjsonfile) as f:
        #ast = json.load(f)
    #else: raise Exception('Unknown input file type. Must be ".sol".')

    #print('readastcompact')
    dataOut = {}
    return {"ast": ast, "version": version}


def iscompilable(infile):
    # Call the compiler first for sol files
    if infile.endswith('.sol'):
        #version = getContractSolVersion(infile)
        #if version:
            #subprocess.call("solc-select use " + version, shell=True)
        output = subprocess.run(['solc', '--bin', '--overwrite', '--output-dir', './', infile], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        #print(f"iscompilable-output: {output}\n")
        # Check if the compilation was successful
        if output.returncode == 0:
            #print("Compilation successful.")
            return True
        else:
            #print("Compilation failed.")
            print("Error:", output.stderr.decode())
            #os.remove(infile)
            return False
        #tmpjsonfile = basename(infile + '_compilable.json')
        #with open(tmpjsonfile) as f:
        #ast = json.load(f)
        #os.remove(tmpjsonfile)
        #print(f"iscompilable-ast: {ast}\n")
    else:
        #raise Exception('Unknown input file type. Must be ".sol".')
        print(f"iscompilable-file is not ending with .sol\n")
        return False

def action(ast, vulnerable_node):
    operation_type = None
    if left.get('nodeType') == 'MemberAccess' and left.get('memberName') == 'sender' and left.get('expression', {}).get('name') == 'msg':
        owner_flag = 'right'
    else:
        owner_flag = 'left'
    if owner_flag == 'right':
        owner_part = vulnerable_node['rightExpression'] if vulnerable_node.get('rightExpression') else None
        if not owner_part or owner_part['nodeType'] not in ['Identifier','FunctionCall']:
            print("action-Unable to identify 'owner' part in the vulnerable node.")
            return None
        # Build the replacement node
        tx_origin_equals_owner_node = {
            "nodeType": "BinaryOperation",
            "operator": "==",
            "leftExpression": {
                "nodeType": "MemberAccess",
                "expression": {
                    "nodeType": "Identifier",
                    "name": "tx",
                    "typeDescriptions": {
                        "typeIdentifier": "t_magic_transaction",
                        "typeString": "tx"
                    }
                },
                "memberName": "origin",
                "typeDescriptions": {
                    "typeIdentifier": "t_address_payable",
                    "typeString": "address payable"
                }
            },
            "rightExpression": owner_part,  # Reuse the 'owner' part from the vulnerable node
            "typeDescriptions": {
                "typeIdentifier": "t_bool",
                "typeString": "bool"
            }
        }
    else:
        owner_part = vulnerable_node['leftExpression'] if vulnerable_node.get('leftExpression') else None
        if not owner_part or owner_part['nodeType'] not in ['Identifier','FunctionCall']:
            print("action-Unable to identify 'owner' part in the vulnerable node.")
            return None
        # Build the replacement node
        tx_origin_equals_owner_node = {
            "nodeType": "BinaryOperation",
            "operator": "==",
            "leftExpression": owner_part,  # Reuse the 'owner' part from the vulnerable node
            "rightExpression": {
                "nodeType": "MemberAccess",
                "expression": {
                    "nodeType": "Identifier",
                    "name": "tx",
                    "typeDescriptions": {
                        "typeIdentifier": "t_magic_transaction",
                        "typeString": "tx"
                    }
                },
                "memberName": "origin",
                "typeDescriptions": {
                    "typeIdentifier": "t_address_payable",
                    "typeString": "address payable"
                }
            },
            "typeDescriptions": {
                "typeIdentifier": "t_bool",
                "typeString": "bool"
            }
        }
    return tx_origin_equals_owner_node, operation_type

def main():
    parser = argparse.ArgumentParser(description='Verify Solidity smart contracts.',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('input', type=str, help='Path to the input file in JSON or .sol format')
    parser.add_argument('output', type=str, help='Path to the output (.sol) file')
    args = parser.parse_args()
    result = readastcompact(args.input)
    print('mainserializer')
    print(result["ast"])
    writeast(result["ast"], args.output, result["version"])


if __name__ == "__main__":
    main()
