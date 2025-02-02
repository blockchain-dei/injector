#!/usr/bin/env python3
 
from common import mainfunc
import copy
'''
Vulnerability: 5.6.2 Function return type mismatch
source: https://openscv.dei.uc.pt/

condition function task: we need to look for functions which have the same return type in the interface and return call (a vulnerable one would have a mismatched return type)

action function task: 

assumptions:
	- the function which is called, assumed to return a boolean value
	- type of the variable is assumed to be a boolean
    - change the signature of a function
'''

def condition(ast):
    functions_to_modify = []
    for node in traverse_nodes(ast, node_type="FunctionDefinition"):
        if check_bool_return_parameter(node["returnParameters"]) and node["body"] is None:
            functions_to_modify.append(node)
    return functions_to_modify

def traverse_nodes(ast, node_type):
    vulnerable_variables = []
    def traverse(node):
        if isinstance(node, dict):
            if node.get('nodeType') == node_type:
                vulnerable_variables.append(node)
            for value in node.values():
                if isinstance(value, (dict, list)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)

    traverse(ast)
    #print(f"condition - vulnerable_nodes: {vulnerable_variables}\n")
    return vulnerable_variables

def check_bool_return_parameter(return_parameters):
    # Check if 'parameters' is in return_parameters and it contains at least one parameter
    if 'parameters' in return_parameters and len(return_parameters['parameters']) > 0:
        for parameter in return_parameters['parameters']:
            # Check the parameter's type
            if 'typeDescriptions' in parameter and parameter['typeDescriptions']['typeString'] == 'bool':
                return True
            elif 'typeName' in parameter and 'name' in parameter['typeName'] and parameter['typeName']['name'] == 'bool':
                return True
    # If there are no parameters or no parameter of type bool, return False
    return False


def modify_function_return_type(node, vulnerable_node_id, old_type, new_type):
    """Modify the function definition by removing 'Return' statements, if it matches the given ID."""
    if node["nodeType"] == "FunctionDefinition" and node["id"] == vulnerable_node_id:
        for param in node.get('returnParameters', {}).get('parameters', []):
                if param.get('typeName', {}).get('name') == old_type:
                    # Modify the return type
                    param['typeName']['name'] = new_type
                    # Assuming 'typeDescriptions' field needs update
                    param['typeName']['typeDescriptions'] = {'typeString': new_type, 'typeIdentifier': f't_{new_type.lower()}'}
        return node
    return None


def traverse_and_modify(ast, vulnerable_node_id):
    """Traverse the AST recursively to find and modify the vulnerable node."""
    #print(f"traverse_and_modify-ast: {ast}\n")
    # Check if the current node matches the criteria
    modified_node = modify_function_return_type(ast, vulnerable_node_id, 'bool', 'address')
    if modified_node:
        return modified_node
    '''
    # If the node has child nodes, traverse them
    if "nodes" in ast:
        for child_node in ast["nodes"]:
            result = traverse_and_modify(child_node, vulnerable_node_id)
            if result:
                return result
    elif "body" in ast and ast["body"] is not None and "statements" in ast["body"]:  # For nodes with a 'body' that contains 'statements'
        for stmt in ast["body"]["statements"]:
            result = traverse_and_modify(stmt, vulnerable_node_id)
            if result:
                return result
    '''
    return None

def action(ast, vulnerable_node):
    operation_type = None #'replace'
    """Find and modify the specified function definition node to remove its 'Return' statements."""
    ast_copy = copy.deepcopy(ast)  # Deep copy the AST to safely modify it
    return traverse_and_modify(ast_copy, vulnerable_node["id"]), operation_type

if __name__ == "__main__":
    mainfunc('5-6-2', condition, action, '5-6-2')
"""
5.6.2
fixed code:

 function ownerOf(uint256 _tokenId) external view returns (boolean){
 
 	return true;
 
 }
 
 
 vulnerable code:
 function ownerOf(uint256 _tokenId) external view returns (address){
 
 	return true;
 
 } """

#operation_type (delete, replace, add)