#!/usr/bin/env python3

from commonc import mainfunc
import copy

'''
Vulnerability: 8.1.2 Owner Manipulation source: https://openscv.dei.uc.pt/

condition function task: identify any function call of specific contract inside another contract which is assigned to a variable.

action function task: turn one statement into two independent statements.first statement is the variable part which is supposed to ba boolean and we assign "true" value to cover any kind of usage of that variable and possible business logic.
second statement would be the function call without caring about its return value. actually we assume that the function call return a boolean value. in this way we create a vulnerable contract due to not checking the return value of that specific function call.
'''

def conditionold2(ast):
    nodes_to_return = []
    owner_variable_name = None

    # Check for state variable named "owner" or assigned with "msg.sender" that isn't reassigned
    for node in ast:
        #print(f"condition-node: {node}")
        if 'nodeType' in node and node['nodeType'] == 'VariableDeclaration' and node['visibility'] != 'public':
            for declaration in node['declarations']:
                if declaration['name'] == 'owner' or declaration['value'] == 'msg.sender':
                    owner_variable_name = declaration['name']
                    nodes_to_return.append(node)

    # Check that the owner isn't reassigned in a public function
    for node in ast:
        if 'nodeType' in node and node['nodeType'] == 'FunctionDefinition' and node['visibility'] == 'public':
            if any(owner_variable_name in statement for statement in node['body']):
                nodes_to_return.remove(node)

    print(f"condition-nodes_to_return: {nodes_to_return}")
    return nodes_to_return
    
def find_variables3(ast):
    """
    Search for state variables named 'owner' or variables assigned 'msg.sender'.
    Returns a list of variables found.
    """
    variables = []
    
    def traverse(node, parent=None):
        # Check for 'owner' state variable declaration
        if node.get('nodeType') == 'VariableDeclaration' and node.get('stateVariable', False):
            # Check if the variable is named 'owner' and is not public
            if node.get('name') == 'owner' and node.get('visibility', 'public') != 'public':
                variables.append({'type': 'state_variable', 'id': node['id'], 'name': 'owner'})
            # Check if the variable is assigned 'msg.sender'
            elif 'value' in node:
                value = node['value']
                if isinstance(value, dict) and value.get('nodeType') == 'FunctionCall':
                    expression = value.get('expression')
                    if isinstance(expression, dict) and expression.get('nodeType') == 'MemberAccess':
                        if expression.get('expression', {}).get('name') == 'msg' and expression.get('memberName') == 'sender':
                            variables.append({'type': 'msg.sender_assignment', 'id': node['id'], 'name': node.get('name')})

        # Recursively check children
        for key, value in node.items():
            if isinstance(value, dict):
                traverse(value, node)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        traverse(item, node)

    traverse(ast)
    return variables
    
def condition(ast):
    results = []
    state_vars = {}
    
    def traverse(node, context=None):
        # Check for state variable declarations of type 'address'
        if (node.get("nodeType") == "VariableDeclaration" and
            node.get("stateVariable", False) and
            node.get("typeName", {}).get("name") == "address" and node.get('constant') is False):
            # Check if it's assigned 'msg.sender' directly or in certain contexts
            if node.get('name') == 'owner': #and node.get('visibility', 'public') != 'public':
            	results.append(node)
            elif (node.get("value") is not None and
                isinstance(node.get("value"), dict) and node["value"].get("nodeType", {}) == "MemberAccess" and
                node["value"].get("memberName", {}) == "sender" and
                node["value"].get("expression", {}).get("name") == "msg"):
                print(f"condition1-node: {node}\n")
                results.append(node)
            elif (node.get("value") is not None and
                isinstance(node.get("value"), dict) and node["value"].get("nodeType", {}) == "Literal"):
                results.append(node)
            elif node.get("value") is None:
            	state_vars[node['id']] = node
        
        # Traverse into function definitions to check for assignments or usage in constructors or modifiers
        if node.get("nodeType") == "FunctionDefinition":
            new_context = "constructor" if node.get("name") == "" or ('isConstructor' in node and node['isConstructor'] is True) or node.get('kind') == 'constructor' else None
            if new_context is not None:
            	#print(f"condition-node: {node}\n")
            	check_constructor(node)


        # Traverse into modifiers to check for comparisons or assignments
        if node.get("nodeType") == "ModifierDefinition":
            for statement in node.get("body", {}).get("statements", []):
                traverse(statement, context="modifier")

        # General recursive case for all other nodes
        for key, value in node.items():
            if isinstance(value, dict):
                traverse(value, context=context)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        traverse(item, context=context)

    def check_constructor(node):
        # Explore the body of the constructor
        body = node.get("body", {}).get("statements", [])
        for statement in body:
            if statement.get("nodeType") == "ExpressionStatement":
                expr = statement.get("expression", {})
                if expr.get("nodeType") == "Assignment":
                    left_hand_side = expr.get("leftHandSide", {})
                    right_hand_side = expr.get("rightHandSide", {})
                    # Check if right hand is 'msg.sender' or a literal and left hand is a state var
                    if (is_msg_sender(right_hand_side) or is_literal(right_hand_side)) and left_hand_side.get("referencedDeclaration") in state_vars:
                        results.append(state_vars[left_hand_side.get("referencedDeclaration")])

    def is_msg_sender(node):
        # Check if the node represents 'msg.sender'
        return (node.get("nodeType") == "MemberAccess" and
                node.get("memberName") == "sender" and
                node.get("expression", {}).get("name") == "msg")

    def is_literal(node):
        # Check if the node is a literal (numeric or string)
        return node.get("nodeType") == "Literal"
        
    traverse(ast)
    return results
    
def condition22(ast):
    results = []
    state_vars = {}
    
    def traverse(node, context=None):
        # Check for state variable declarations of type 'address'
        if (node.get("nodeType") == "VariableDeclaration" and
            node.get("stateVariable", False) and
            node.get("typeName", {}).get("name") == "address" and node.get('constant') is False):
            # Check if it's assigned 'msg.sender' directly or in certain contexts
            if node.get('name') == 'owner' and node.get('visibility', 'public') != 'public':
            	results.append(node)
            elif (node.get("value") is not None and
                isinstance(node.get("value"), dict) and node["value"].get("nodeType", {}) == "MemberAccess" and
                node["value"].get("memberName", {}) == "sender" and
                node["value"].get("expression", {}).get("name") == "msg"):
                print(f"condition1-node: {node}\n")
                results.append(node)
            elif (node.get("value") is not None and
                isinstance(node.get("value"), dict) and node["value"].get("nodeType", {}) == "Literal"):
                results.append(node)
            elif node.get("value") is None:
            	state_vars[node['id']] = node
            elif context in ["constructor", "modifier"]:
                print(f"condition2-node: {node}\n")
                results.append(node)
        
        # Traverse into function definitions to check for assignments or usage in constructors or modifiers
        if node.get("nodeType") == "FunctionDefinition":
            new_context = "constructor" if node.get("name") == "" or ('isConstructor' in node and node['isConstructor'] is True) or node.get('kind') == 'constructor' else None
            if new_context is not None:
            	#print(f"condition-node: {node}\n")
            	for statement in node.get("body", {}).get("statements", []):
                	traverse(statement, context=new_context)

        # Traverse into modifiers to check for comparisons or assignments
        if node.get("nodeType") == "ModifierDefinition":
            for statement in node.get("body", {}).get("statements", []):
                traverse(statement, context="modifier")

        # General recursive case for all other nodes
        for key, value in node.items():
            if isinstance(value, dict):
                traverse(value, context=context)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        traverse(item, context=context)

    traverse(ast)
    return results
    
def find_variables(ast):
    """
    Search for state variables named 'owner' or variables assigned 'msg.sender'.
    Returns a list of dictionaries with the type of match and the node ID.
    """
    variables = []
    
	
    def traverse(node, parent=None):
        # Check for 'owner' state variable declaration
        owner_variable_name = None
        #print(f"condition-node: {node}")
        #print(f"condition-1")
        if (node.get('nodeType') == 'VariableDeclaration' and node.get('stateVariable', False) and node.get('visibility') != 'public'):
            if node.get('name') == 'owner':
            	print(f"condition-2")
            	owner_variable_name = node.get('name')
            	variables.append(node)
            elif 'value' in node:
                value = node['value']
                if isinstance(value, dict) and value.get('nodeType') == 'FunctionCall':
                    expression = value.get('expression')
                    if isinstance(expression, dict) and expression.get('nodeType') == 'MemberAccess':
                        if expression.get('expression', {}).get('name') == 'msg' and expression.get('memberName') == 'sender':
                        	print(f"condition-3")
                        	owner_variable_name = node.get('name')
                        	variables.append(node)
            				
        # Check for variables assigned 'msg.sender'
        if (owner_variable_name and node.get('nodeType') == 'FunctionDefinition' and
              node['visibility'] == 'public'):
            # Ensure we capture the variable being assigned 'msg.sender'
             if any(owner_variable_name in statement for statements in node['body']):
                print(f"condition-4")
                variables.remove(node)
        # Recurse through children
        for key, value in node.items():
            if isinstance(value, dict):
                traverse(value, node)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        traverse(item, node)

    traverse(ast)
    return variables
    
def find_variables2(ast):
    """
    Search for state variables named 'owner' or variables assigned 'msg.sender'.
    Returns a list of dictionaries with the type of match and the node ID.
    """
    variables = []
    
	
    def traverse(node, parent=None):
        # Check for 'owner' state variable declaration
        owner_variable_name = None
        #print(f"condition-node: {node}")
        if (node.get('nodeType') == 'VariableDeclaration' and node.get('stateVariable', False) and node.get('visibility') != 'public'):
            if node.get('name') == 'owner' or ('value' in node and node['value'].get('expression', {}).get('name') == 'msg' and node['value'].get('memberName') == 'sender'):
            	owner_variable_name = node.get('name')
            	variables.append(node)
        # Check for variables assigned 'msg.sender'
        if (owner_variable_name and node.get('nodeType') == 'FunctionDefinition' and
              node['visibility'] == 'public'):
            # Ensure we capture the variable being assigned 'msg.sender'
             if any(owner_variable_name in statement for statements in node['body']):
                variables.remove(node)
        # Recurse through children
        for key, value in node.items():
            if isinstance(value, dict):
                traverse(value, node)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        traverse(item, node)

    traverse(ast)
    return variables
    
def find_variablesold(ast):
    """
    Search for state variables named 'owner' or variables assigned 'msg.sender'.
    Returns a list of dictionaries with the type of match and the node ID.
    """
    variables = []

    def traverse(node, parent=None):
        # Check for 'owner' state variable declaration
        if node.get('nodeType') == 'VariableDeclaration' and node.get('stateVariable', False) and node.get('name') == 'owner' and node.get('visibility') != 'public':
            variables.append(node)
        # Check for variables assigned 'msg.sender'
        elif (node.get('nodeType') == 'VariableDeclarationStatement' and
              'initialValue' in node and
              node['initialValue'].get('expression', {}).get('name') == 'msg' and
              node['initialValue'].get('memberName') == 'sender'):
            # Ensure we capture the variable being assigned 'msg.sender'
            for declaration in node.get('declarations', []):
                variables.append({'type': 'msg.sender', 'id': declaration['id']})
        # Recurse through children
        for key, value in node.items():
            if isinstance(value, dict):
                traverse(value, node)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        traverse(item, node)

    traverse(ast)
    return variables

def condition5(ast):
    nodes_to_modify = find_variables(ast)
    #print(f"Found variables to modify: {nodes_to_modify}")
    return nodes_to_modify


def conditionold(ast):
    nodes_to_modify = []
    has_owner_variable = False
    assigned_msg_sender = False

    # Iterate through AST nodes to check for the specified patterns
    for node in ast['nodes']:
        if node['nodeType'] == 'VariableDeclaration' and node['name'] == 'owner':
            has_owner_variable = True
        if node['nodeType'] == 'FunctionDefinition' and node['visibility'] == 'public':
            # Simplified check for assignment to owner or msg.sender usage
            if any('owner =' in s or 'msg.sender' in s for s in extract_statements(node)):
                assigned_msg_sender = True
    
    # Determine the pattern
    if has_owner_variable and not assigned_msg_sender:
        nodes_to_modify.append({'type': 1, 'node': None})  # Type 1 for adding function to assign msg.sender to owner
    elif not has_owner_variable and assigned_msg_sender:
        nodes_to_modify.append({'type': 2, 'node': None})  # Type 2 for adding owner variable and function
    elif not has_owner_variable and not assigned_msg_sender:
        nodes_to_modify.append({'type': 3, 'node': None})  # Type 3 for adding owner variable, its assignment, and function
    
    print(f"condition-has_owner_variable: {has_owner_variable}\n")
    print(f"condition-assigned_msg_sender: {assigned_msg_sender}\n")
    print(f"condition-nodes_to_modify: {nodes_to_modify}\n")
    return nodes_to_modify

def action(ast, node):
    new_nodes = []
    operation_type = None
    owner_variable_name = node.get('name')
    new_function_node = create_public_function_node(f"set{owner_variable_name.capitalize()}", owner_variable_name)
    #print(f"action-new_function_node: {new_function_node}\n")
    new_nodes.append(new_function_node)
    operation_type = 'add'  # Since we are adding a new function

    return new_nodes, operation_type


def actionold2(ast, nodes):
    new_nodes = []
    operation_type = None

    for node in nodes:
        owner_variable_name = node['declarations'][0]['name']
        new_function = {
            'nodeType': 'FunctionDefinition',
            'name': f'set{owner_variable_name.capitalize()}',
            'parameters': [],
            'modifiers': ['public'],
            'body': [
                {'type': 'ExpressionStatement', 'expression': {'type': 'Assignment', 'left': owner_variable_name, 'right': 'msg.sender'}}
            ]
        }
        new_nodes.append(new_function)
        operation_type = 'add'  # Since we are adding a new function

    return new_nodes, operation_type
    
def actionold(ast, node_to_modify):
    # Depending on the type of modification, perform different actions
    print(f"action-node_to_modify: {node_to_modify}\n")
    modification_type = node_to_modify['type']
    node_id = node_to_modify['id']  # Use the ID to identify where to apply the modification
    
    new_nodes = []
    
    if modification_type == 1:
        # Add a public function to assign msg.sender to owner
        new_function_node = create_public_function_node("setOwner", "owner = msg.sender;")
        new_nodes.append(new_function_node)
        
    elif modification_type == 2 or modification_type == 3:
        # For type 2 and 3, the actions could be similar, but type 3 requires adding the owner variable
        if modification_type == 3:
            owner_variable_node = create_variable_declaration_node("owner", "address", "private", "msg.sender")
            new_nodes.append(owner_variable_node)
        
        # Add a public function for assignment to owner
        new_function_node = create_public_function_node("setOwner", "owner = msg.sender;")
        new_nodes.append(new_function_node)
    
    return new_nodes

def create_variable_declaration_node(name, var_type, visibility, initial_value=None):
    node = {
        "constant": False,
        "id": None,  # ID needs to be assigned based on AST context
        "mutability": "mutable",
        "name": name,
        "nodeType": "VariableDeclaration",
        "scope": None,  # Scope ID needs to be assigned based on AST context
        "src": "",  # Source location string (to be calculated or assigned)
        "stateVariable": True,
        "storageLocation": "default",
        "typeDescriptions": {
            "typeIdentifier": f"t_{var_type}",
            "typeString": var_type
        },
        "typeName": {
            "id": None,  # ID needs to be assigned based on AST context
            "name": var_type,
            "nodeType": "ElementaryTypeName",
            "src": "",  # Source location string (to be calculated or assigned)
            "stateMutability": "nonpayable",
            "typeDescriptions": {
                "typeIdentifier": f"t_{var_type}",
                "typeString": var_type
            }
        },
        "visibility": visibility
    }

    if initial_value:
        value_node = {
            "expression": {
                "id": None,  # ID for 'msg' identifier, needs to be assigned based on AST context
                "name": "msg",
                "nodeType": "Identifier",
                "overloadedDeclarations": [],
                "referencedDeclaration": -15,  # Magic value for 'msg'
                "src": "",  # Source location string (to be calculated or assigned)
                "typeDescriptions": {
                    "typeIdentifier": "t_magic_message",
                    "typeString": "msg"
                }
            },
            "id": None,  # ID needs to be assigned based on AST context
            "memberName": "sender",
            "nodeType": "MemberAccess",
            "src": "",  # Source location string (to be calculated or assigned)
            "typeDescriptions": {
                "typeIdentifier": "t_address",
                "typeString": "address"
            }
        }
        node['value'] = value_node

    return node


def create_public_function_node(name, varName, visibility='public'):
    node = {
        "body": {
            "id": None,  # ID needs to be assigned based on AST context
            "nodeType": "Block",
            "src": "",  # Source location string (to be calculated or assigned)
            "statements": [
                {
                    "expression": {
                        "id": None,  # ID needs to be dynamically assigned
                        "nodeType": "Assignment",
                        "operator": "=",
                        "leftHandSide": {
                            "id": None,  # ID for 'owner' identifier, needs to be assigned
                            "name": varName,#"owner",
                            "nodeType": "Identifier",
                            "referencedDeclaration": None,  # 'owner' variable declaration ID
                            "src": "",  # Source location string
                        },
                        "rightHandSide": {
                            "expression": {
                                "id": None,  # ID for 'msg' identifier
                                "name": "msg",
                                "nodeType": "Identifier",
                                "referencedDeclaration": -15,  # Magic value for 'msg'
                                "src": "",  # Source location string
                            },
                            "memberName": "sender",
                            "nodeType": "MemberAccess",
                            "src": "",  # Source location string
                        },
                        "src": "",  # Source location string
                    },
                    "id": None,  # ID needs to be dynamically assigned
                    "nodeType": "ExpressionStatement",
                    "src": "",  # Source location string
                }
            ]
        },
        "id": None,  # ID needs to be dynamically assigned
        "implemented": True,
        "kind": "function",
        "modifiers": [],
        "name": name,
        "nodeType": "FunctionDefinition",
        "parameters": {"id": None, "nodeType": "ParameterList", "parameters": [], "src": ""},
        "returnParameters": {"id": None, "nodeType": "ParameterList", "parameters": [], "src": ""},
        "scope": None,  # Scope ID needs to be assigned based on AST context
        "src": "",  # Source location string
        "stateMutability": "nonpayable",
        "visibility": visibility
    }

    return node
            
if __name__ == "__main__":
    mainfunc('8-1-2', condition, action, '8-1-2')