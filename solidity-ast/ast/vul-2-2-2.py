#!/usr/bin/env python3

from common import mainfunc

'''
Vulnerability: 2.2.2 Extraneous Exception Handling source: https://openscv.dei.uc.pt/

assumption: identify "functionDefinition" nodeType with specific condition:
    + has signature: (address _from, address _to, uint _value)
    + nodeType : "FunctionDefinition"
    + emit event (from 0.4.21 ahead)

action function task: add an "assert" node expected in solidity standard
'''

def is_target_call_value(node):
    
    if node.get("nodeType") == "FunctionDefinition":
        # Check if body is not None because need to iter inside it to looking for the "Transfer" event
        if node.get("body") and 'statements' in node['body']:
            has_transfer_event = False
            for statement in node['body']['statements']:
                if statement.get("nodeType") == "EmitStatement":
                    event_call = statement.get("eventCall", {})
                    if event_call.get("expression", {}).get("name") == "Transfer":
                        has_transfer_event = True
                        break

            parameters = node.get("parameters", {}).get("parameters", [])
            has_address_and_uint = (
                len(parameters) == 3 and
                parameters[0].get("typeName", {}).get("typeDescriptions", {}).get("typeString") == "address" and
                parameters[1].get("typeName", {}).get("typeDescriptions", {}).get("typeString") == "address" and
                parameters[2].get("typeName", {}).get("typeDescriptions", {}).get("typeString") == "uint256"
            )

            return has_transfer_event and has_address_and_uint
    return False

def condition(ast):

    matches = []
 
    def traverse(node):
        # Recursively traverse the AST to find nodes
        if isinstance(node, dict):
            if is_target_call_value(node):
                matches.append(node)
            for value in node.values():
                if isinstance(value, (dict, list)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)

    traverse(ast)
    return matches

def action(ast, target_node):

    operation_type = None
    
    new_require = {
    "expression": {
        "arguments": [
            {
                "commonType": {"typeIdentifier": "t_uint256", "typeString": "uint256"},
                "id": 44,
                "leftExpression": {
                    "id": 45,
                    "name": "_value",
                    "nodeType": "Identifier",
                    "referencedDeclaration": 3,
                    "src": "148:6:0",
                    "typeDescriptions": {"typeIdentifier": "t_uint256", "typeString": "uint256"}
                },
                "nodeType": "BinaryOperation",
                "operator": "<",
                "rightExpression": {
                    "hexValue": "3230",
                    "id": 46,
                    "kind": "number",
                    "nodeType": "Literal",
                    "src": "157:6:0",
                    "subdenomination": "wei",
                    "typeDescriptions": {"typeIdentifier": "t_rational_20_by_1", "typeString": "int_const 20"},
                    "value": "20"
                },
                "typeDescriptions": {"typeIdentifier": "t_bool", "typeString": "bool"}
            }
        ],
        "expression": {
            "id": 47,
            "name": "require",
            "nodeType": "Identifier",
            "src": "140:7:0",
            "typeDescriptions": {
                "typeIdentifier": "t_function_require_pure$_t_bool_$returns$__$",
                "typeString": "function (bool) pure"
            }
        },
        "id": 48,
        "nodeType": "FunctionCall",
        "src": "140:24:0",
        "typeDescriptions": {"typeIdentifier": "t_tuple$__$", "typeString": "tuple()"}
    },
    "id": 49,
    "nodeType": "ExpressionStatement",
    "src": "140:24:0"
}

    # Add the node "require" as first statement of the body
    if "body" in target_node and "statements" in target_node["body"]:
        target_node["body"]["statements"].insert(0, new_require)
    
    return [target_node], operation_type
    

if __name__ == "__main__":
    mainfunc('2-2-2', condition, action, '2-2-2')