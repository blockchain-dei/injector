#!/usr/bin/env python3

from common import mainfunc
import copy

'''
Vulnerability: 8.1.2 Owner Manipulation source: https://openscv.dei.uc.pt/

condition function task: identify any function call of specific contract inside another contract which is assigned to a variable.

action function task: turn one statement into two independent statements.first statement is the variable part which is supposed to ba boolean and we assign "true" value to cover any kind of usage of that variable and possible business logic.
second statement would be the function call without caring about its return value. actually we assume that the function call return a boolean value. in this way we create a vulnerable contract due to not checking the return value of that specific function call.
'''


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
    
    
def action(ast, node):
    new_nodes = []
    operation_type = None
    owner_variable_name = node.get('name')
    new_function_node = create_public_function_node(f"set{owner_variable_name.capitalize()}", owner_variable_name)
    #print(f"action-new_function_node: {new_function_node}\n")
    new_nodes.append(new_function_node)
    operation_type = 'add'  # Since we are adding a new function

    return new_nodes, operation_type



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