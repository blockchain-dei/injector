#!/usr/bin/env python3

from commonc import mainfunc
import copy

'''
Vulnerability: 8.1.1 Wrong Caller Identification source: https://openscv.dei.uc.pt/

condition function task: identify any function call of specific contract inside another contract which is assigned to a variable.

action function task: turn one statement into two independent statements.first statement is the variable part which is supposed to ba boolean and we assign "true" value to cover any kind of usage of that variable and possible business logic.
second statement would be the function call without caring about its return value. actually we assume that the function call return a boolean value. in this way we create a vulnerable contract due to not checking the return value of that specific function call.
'''

def condition(ast):
    vulnerable_nodes = []

    def search_node(node):
        if isinstance(node, dict):
            # Checking for a BinaryOperation with equality check
            if node.get('nodeType') == 'BinaryOperation' and node.get('operator') == '==':
                left = node.get('leftExpression', {})
                right = node.get('rightExpression', {})
                # Detailed check for msg.sender on both sides of the equation
                if ((left.get('nodeType') == 'MemberAccess' and left.get('memberName') == 'sender' and left.get('expression', {}).get('name') == 'msg') or
                    (right.get('nodeType') == 'MemberAccess' and right.get('memberName') == 'sender' and right.get('expression', {}).get('name') == 'msg')):
                    vulnerable_nodes.append(node)

            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    search_node(value)

        elif isinstance(node, list):
            for item in node:
                search_node(item)

    search_node(ast)
    #print(f"condition-vulnerable_nodes: {vulnerable_nodes}\n")
    return vulnerable_nodes

def action2(ast, vulnerable_node):
    """
    Constructs a replacement node for 'tx.origin == owner' using information from the vulnerable_node.

    Parameters:
    - ast: The entire AST of the Solidity contract.
    - vulnerable_node: The node representing 'msg.sender == owner'.

    Returns:
    A dictionary representing the AST node for 'tx.origin == owner'.
    """
    operation_type = None
    # Extract the 'owner' identifier from the vulnerable_node
    owner_part = vulnerable_node['rightExpression'] if vulnerable_node.get('rightExpression') else None
    print(f"action-owner_part: {owner_part}\n")
    print(f"action-owner_part-node_type: {owner_part['nodeType']}\n")
    # Verify we have the 'owner' part correctly identified
    #if not owner_part or owner_part['nodeType'] != 'Identifier':
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

    #print(f"action-1{tx_origin_equals_owner_node}\n")
    return tx_origin_equals_owner_node, operation_type

def action(ast, vulnerable_node):
    operation_type = None
    left = vulnerable_node.get('leftExpression', {})
    right = vulnerable_node.get('rightExpression', {})
    if left.get('nodeType') == 'MemberAccess' and left.get('memberName') == 'sender' and left.get('expression', {}).get('name') == 'msg':
        owner_flag = 'right'
    else:
        owner_flag = 'left'
    if owner_flag == 'right':
        owner_part = vulnerable_node['rightExpression'] if vulnerable_node.get('rightExpression') else None
        print(f"action-owner_part: {owner_part}\n")
        print(f"action-owner_part-node_type1: {owner_part['nodeType']}\n")
        if not owner_part or owner_part['nodeType'] not in ['Identifier','FunctionCall','MemberAccess']:
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
        print(f"action-owner_part: {owner_part}\n")
        print(f"action-owner_part-node_type2: {owner_part['nodeType']}\n")
        if not owner_part or owner_part['nodeType'] not in ['Identifier','FunctionCall','MemberAccess']:
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



def actionold2(ast, vulnerable_node):
    # This function will create a modified version of the vulnerable node
    # with msg.sender replaced by tx.origin

    def replace_msg_sender(node):
        # Recursively search for the msg.sender and replace it with tx.origin
        if isinstance(node, dict):
            if (node.get('nodeType') == 'MemberAccess' and node.get('memberName') == 'sender' and 
                node.get('expression', {}).get('name') == 'msg'):
                # This is the msg.sender node, replace it with tx.origin
                print(f"action-1\n")
                #node.get('expression', {}).get('name') = 'tx'
                #node.get('memberName') = 'origin'
            else:
                # Recurse into children nodes
                for key, value in node.items():
                    if isinstance(value, (dict, list)):
                        replace_msg_sender(value)
        elif isinstance(node, list):
            for item in node:
                replace_msg_sender(item)

    # Clone the vulnerable_node to not modify the original AST directly
    #modified_node = copy.deepcopy(vulnerable_node)
    replace_msg_sender(vulnerable_node)
    return vulnerable_node

def actionold(ast, vulnerable_node):
    modified_nodes = []

    # Replace msg.sender with tx.origin in the vulnerable node
    if vulnerable_node['leftExpression'].get('expression', {}).get('memberName') == 'sender':
        print(f"action-1\n")
        vulnerable_node['leftExpression']['expression']['expression']['name'] = 'tx'
        vulnerable_node['leftExpression']['expression']['memberName'] = 'origin'
    elif vulnerable_node['rightExpression'].get('expression', {}).get('memberName') == 'sender':
        print(f"action-2\n")
        vulnerable_node['rightExpression']['expression']['expression']['name'] = 'tx'
        vulnerable_node['rightExpression']['expression']['memberName'] = 'origin'
    
    modified_nodes.append(vulnerable_node)
    return modified_nodes



if __name__ == "__main__":
    mainfunc('8-1-1', condition, action, '8-1-1')