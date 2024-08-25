#!/usr/bin/env python3

from commonc import mainfunc
import copy

'''
Vulnerability: 5.6.1 Missing return type on function source: https://openscv.dei.uc.pt/

condition function task: identify any function call of specific contract inside another contract which is assigned to a variable.

action function task: turn one statement into two independent statements.first statement is the variable part which is supposed to ba boolean and we assign "true" value to cover any kind of usage of that variable and possible business logic.
second statement would be the function call without caring about its return value. actually we assume that the function call return a boolean value. in this way we create a vulnerable contract due to not checking the return value of that specific function call.
'''

def condition(ast):
    functions_to_modify = []
    #print(f"condition-1\n")
    for node in traverse_nodes(ast, node_type="FunctionDefinition"):
        #print(f"condition-node-id: {node["id"]}\n")
        #print(f"condition-node-body: {node["body"]}\n")
        if check_return_parameter(node["returnParameters"]) and contains_return_statement(node["body"]):
            functions_to_modify.append(node)
    #print(f"condition-functions_to_modify: {functions_to_modify}\n")
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
    
def contains_return_statement(node_body):
    # Check if the node is a Block that contains statements
    #print(f"contains_return_statement-node_body-nodeType: {node_body['nodeType']}\n")
    #print(f"contains_return_statement-node_body-nodeType: {node_body["nodeType"]}\n")
    #if node_body["nodeType"] == "Block" and "statements" in node_body:
    if node_body is not None and node_body.get("nodeType") == "Block" and "statements" in node_body:
        for statement in node_body["statements"]:
            # If a Return statement is found, return True
            if statement["nodeType"] == "Return":
                return True
            # If the statement is a Block, recursively search for Return statements within it
            elif statement["nodeType"] == "Block":
                if contains_return_statement(statement):
                    return True
            # If the statement can contain other statements (like if/else, for loops), add additional conditions here
            # Example for an 'If' statement, checking both the true and false blocks if present
            elif statement["nodeType"] == "IfStatement":
                if "trueBody" in statement and contains_return_statement(statement["trueBody"]):
                    return True
                if "falseBody" in statement and contains_return_statement(statement["falseBody"]):
                    return True
    # If no Return statement is found, return False
    return False

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

def check_return_parameter(return_parameters):
    # Check if 'parameters' is in return_parameters and it contains at least one parameter
    if 'parameters' in return_parameters and len(return_parameters['parameters']) > 0:
        return True
    return False
    
def remove_return_statements(statements):
    """Remove 'Return' statements from a list of statements."""
    return [stmt for stmt in statements if stmt['nodeType'] != 'Return']

def modify_function_definition(node, vulnerable_node_id):
    """Modify the function definition by removing 'Return' statements, if it matches the given ID."""
    if node["nodeType"] == "FunctionDefinition" and node["id"] == vulnerable_node_id:
        # Remove 'Return' statements from the function's body
        node["body"]["statements"] = remove_return_statements(node["body"]["statements"])
        return node
    return None

def traverse_and_modify(ast, vulnerable_node_id):
    """Traverse the AST recursively to find and modify the vulnerable node."""
    #print(f"traverse_and_modify-ast: {ast}\n")
    # Check if the current node matches the criteria
    modified_node = modify_function_definition(ast, vulnerable_node_id)
    if modified_node:
        return modified_node
    
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

    return None

def action(ast, vulnerable_node):
    operation_type = 'replace'
    """Find and modify the specified function definition node to remove its 'Return' statements."""
    ast_copy = copy.deepcopy(ast)  # Deep copy the AST to safely modify it
    return traverse_and_modify(ast_copy, vulnerable_node["id"]), operation_type
    
if __name__ == "__main__":
    mainfunc('5-6-1', condition, action, '5-6-1')