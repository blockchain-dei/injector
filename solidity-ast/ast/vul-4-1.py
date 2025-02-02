#!/usr/bin/env python3

from common import mainfunc

'''
Vulnerability: 4.1 Improper Check on Transfer Credit source: https://openscv.dei.uc.pt/

condition function task: bool b = msg.sender.send(bal[msg.sender]);

action function task: 
bool b = true;
msg.sender.send(balances[msg.sender]);
'''

def condition(ast):
    matches = []

    def traverse(node, parent=None):
        # Check if the current node is a function call
        if (isinstance(node, dict) and
            node.get('nodeType') == 'FunctionCall' and
            node.get('expression', {}).get('nodeType') == 'MemberAccess' and
            node['expression'].get('memberName') == 'send'):
            expression = node.get('expression', {}).get('expression', {})
            direct_usage = (expression.get('expression', {}).get('nodeType', {}) == 'Identifier' and
                            expression.get('expression', {}).get('name', {}) == 'msg' and
                            expression.get('memberName', {}) == 'sender')
            wrapped_usage = (expression.get('nodeType') == 'FunctionCall' and
                             expression.get('expression', {}).get('nodeType') == 'ElementaryTypeNameExpression' and
                             expression.get('expression', {}).get('typeName', {}).get('stateMutability') == 'payable')
            wrapped_usage_final = False;
            if wrapped_usage:
            	arguments = expression.get('arguments', [])
            	wrapped_usage_final = False;
            	for argument in arguments:
                    if argument.get('expression', {}).get('name') == 'msg':
                    	wrapped_usage_final = True;
            if direct_usage or wrapped_usage_final:
                if parent and parent.get('nodeType') == 'VariableDeclarationStatement':
                    matches.append(parent)
			
        if isinstance(node, dict):
            for value in node.values():
                traverse(value, node)
        elif isinstance(node, list):
            for item in node:
                traverse(item, parent)

    traverse(ast)
    return matches

def action(ast, target_node):
    operation_type = None
    modified_nodes = []

    # Extract the right-hand side of the assignment (the function call)
    function_call = target_node["initialValue"]
    expression = function_call["expression"]

    # Determine if the call is direct, wrapped in payable, or involves type conversion
    if expression.get('nodeType') == 'MemberAccess':
        is_direct = True
        call_expression = expression
    elif expression.get('nodeType') == 'FunctionCall' and expression.get('expression', {}).get('nodeType') == 'ElementaryTypeNameExpression':
        is_direct = False
        call_expression = expression.get('arguments')[0].get('expression')
    else:
        raise ValueError("Unsupported function call structure")

    # Prepare the new assignment node (bool variable = true;)
    new_assignment = {
        "nodeType": "ExpressionStatement",
        "expression": {
            "nodeType": "Assignment",
            "operator": "=",
            "leftHandSide": target_node["declarations"][0],
            "rightHandSide": {
                "nodeType": "Literal",
                "value": "true",
                "kind": "bool"
            }
        }
    }

    # Prepare the new send call expression
    send_call = {
        "documentation": {
            "id": 1462,
            "nodeType": "StructuredDocumentation",
            "src": "16553:231:0",
            "text": " @notice vuln,4-1,change,functioncall,function"
          },
        "nodeType": "ExpressionStatement",
        "expression": {
            "nodeType": "FunctionCall",
            "expression": call_expression,  # Directly use the unwrapped or direct call expression
            "arguments": function_call["arguments"],
            "names": [],
            "kind": "functionCall"
        }
    }

    # Add the modified nodes
    modified_nodes.append(new_assignment)
    modified_nodes.append(send_call)

    #modified_nodes.append(target_node)
    return modified_nodes, operation_type

if __name__ == "__main__":
    mainfunc('4-1', condition, action, '4-1')