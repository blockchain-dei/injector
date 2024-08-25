#!/usr/bin/env python3

from commonc import mainfunc
import copy

'''
Vulnerability: 7.3.1 Truncation Bugs source: https://openscv.dei.uc.pt/

condition function task: identify any function call of specific contract inside another contract which is assigned to a variable.

action function task: turn one statement into two independent statements.first statement is the variable part which is supposed to ba boolean and we assign "true" value to cover any kind of usage of that variable and possible business logic.
second statement would be the function call without caring about its return value. actually we assume that the function call return a boolean value. in this way we create a vulnerable contract due to not checking the return value of that specific function call.
'''

def condition(ast):
    nodes_to_change = []

    def traverse(node):
        if isinstance(node, dict):
            if node.get('nodeType') in ['VariableDeclaration', 'ParameterList']:
                if 'uint256' in node.get('typeName', {}).get('typeDescriptions', {}).get('typeString', ''):
                    nodes_to_change.append(node)
            elif node.get('nodeType') == 'FunctionDefinition':
                parameters = node.get('parameters', {}).get('parameters', [])
                return_parameters = node.get('returnParameters', {}).get('parameters', [])
                for param in parameters + return_parameters:
                    if 'uint256' in param.get('typeName', {}).get('typeDescriptions', {}).get('typeString', ''):
                        nodes_to_change.append(param)
            for value in node.values():
                if isinstance(value, (dict, list)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)

    traverse(ast)
    print(f"condition-nodes_to_change: {nodes_to_change}\n")
    return nodes_to_change

def action_for_simple_variable(node):
    # Modify the typeDescriptions field
    if 'typeDescriptions' in node:
        node['typeDescriptions']['typeString'] = node['typeDescriptions']['typeString'].replace('uint256', 'uint32')
        node['typeDescriptions']['typeIdentifier'] = node['typeDescriptions']['typeIdentifier'].replace('uint256', 'uint32')
    
    # Modify the typeName field
    if 'typeName' in node and 'typeDescriptions' in node['typeName']:
        node['typeName']['typeDescriptions']['typeString'] = node['typeName']['typeDescriptions']['typeString'].replace('uint256', 'uint32')
        node['typeName']['name'] = 'uint32'
        #node['typeName']['typeDescriptions']['typeIdentifier'] = node['typeName']['typeDescriptions']['typeIdentifier'].replace('uint256', 'uint32')
    
    return node

def action_for_mapping(node):
    # Check if the node represents a mapping
    print(f"action - node: {node}\n")
    if node.get('typeName', {}).get('nodeType') == 'Mapping':
        valueType = node['typeName'].get('valueType', {})
        
        # Check if the value type is uint256
        type_string = valueType.get('typeDescriptions', {}).get('typeString', '')
        if 'uint256' in type_string:
            # Safe update of type descriptions
            valueType['typeDescriptions']['typeString'] = type_string.replace('uint256', 'uint32')
            type_identifier = valueType['typeDescriptions'].get('typeIdentifier', '')
            valueType['typeDescriptions']['typeIdentifier'] = type_identifier.replace('uint256', 'uint32')
            
            # Check and update 'name' only if it exists
            if 'name' in valueType:
                valueType['name'] = valueType['name'].replace('uint256', 'uint32')
            
            # Update the typeName to reflect changes in the AST for easier serialization back to source code
            node_type_string = node['typeName']['typeDescriptions'].get('typeString', '')
            node['typeName']['typeDescriptions']['typeString'] = node_type_string.replace('uint256', 'uint32')
            
            node_type_string_global = node.get('typeDescriptions', {}).get('typeString', '')
            node['typeDescriptions']['typeString'] = node_type_string_global.replace('uint256', 'uint32')
    
    return node

def action_for_mapping2(node):
    # Check if the node represents a mapping with uint256 as the value type
    print(f"action - node: {node}\n")
    if node.get('typeName', {}).get('nodeType') == 'Mapping' and 'uint256' in node.get('typeName', {}).get('valueType', {}).get('typeDescriptions', {}).get('typeString', ''):
        # Update the valueType of the mapping
        node['typeName']['valueType']['typeDescriptions']['typeString'] = node['typeName']['valueType']['typeDescriptions']['typeString'].replace('uint256', 'uint32')
        node['typeName']['valueType']['typeDescriptions']['typeIdentifier'] = node['typeName']['valueType']['typeDescriptions']['typeIdentifier'].replace('uint256', 'uint32')
        node['typeName']['valueType']['name'] = node['typeName']['valueType']['name'].replace('uint256', 'uint32')
        
        # Update the typeName to reflect changes in the AST for easier serialization back to source code
        node['typeName']['typeDescriptions']['typeString'] = node['typeName']['typeDescriptions']['typeString'].replace('uint256', 'uint32')
        node['typeDescriptions']['typeString'] = node['typeDescriptions']['typeString'].replace('uint256', 'uint32')
    
    return node

def action(ast, node):
    operation_type = None
    if node.get('nodeType') == 'VariableDeclaration':
        if node.get('typeName', {}).get('nodeType') == 'Mapping':
        	updated_node = action_for_mapping(node)
        else:
        	updated_node = action_for_simple_variable(node)
    print(f"action - updated_node: {updated_node}\n")
    return updated_node, operation_type


def actionold2(ast, node):
    modified_node = dict(node)  # Create a shallow copy to modify
    
    # Check if it's a mapping with uint256, which needs special handling
    if node.get('nodeType') == 'VariableDeclaration' and node.get('typeName', {}).get('nodeType') == 'Mapping':
        valueType = node['typeName']['valueType']
        if valueType.get('typeDescriptions', {}).get('typeString') == 'uint256':
            # Update the valueType for the mapping
            modified_valueType = dict(valueType)
            modified_valueType['name'] = 'uint32'
            modified_valueType['typeDescriptions']['typeString'] = 'uint32'
            modified_valueType['typeDescriptions']['typeIdentifier'] = modified_valueType['typeDescriptions']['typeIdentifier'].replace('uint256', 'uint32')
            modified_node['typeName']['valueType'] = modified_valueType
    elif 'uint256' in node.get('typeName', {}).get('typeDescriptions', {}).get('typeString', ''):
        # Direct update for non-mapping uint256 variables
        modified_node['typeName']['name'] = 'uint32'
        modified_node['typeName']['typeDescriptions']['typeString'] = 'uint32'
        modified_node['typeName']['typeDescriptions']['typeIdentifier'] = modified_node['typeName']['typeDescriptions']['typeIdentifier'].replace('uint256', 'uint32')
        # Update any other relevant fields if necessary

    return [modified_node]
    
def actionold(ast, node):
    if node.get('nodeType') in ['VariableDeclaration', 'FunctionDefinition', 'ParameterList']:
        print(f"action - 1\n")
        modified_node = dict(node)  # Create a shallow copy to modify
        print(f"action - 2\n")
        if 'uint256' in modified_node.get('typeName', {}).get('typeDescriptions', {}).get('typeString', ''):
            # Update the type string
            print(f"action - 3\n")
            modified_node['typeName']['typeDescriptions']['typeString'] = modified_node['typeName']['typeDescriptions']['typeString'].replace('uint256', 'uint32')
            print(f"action - {modified_node['typeName']['typeDescriptions']['typeString']}\n")
            print(f"action - modified_node: {modified_node}\n")
            # Update any other relevant fields if necessary
        return [modified_node]
    return [node]


if __name__ == "__main__":
    mainfunc('7-3-1', condition, action, '7-3-1')