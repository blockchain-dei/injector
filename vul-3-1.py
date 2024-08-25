#!/usr/bin/env python3

from commonc import mainfunc

'''
Vulnerability: 3.1 Improper Gas Requirements Checking source: https://openscv.dei.uc.pt/

condition function task: identify any function call of specific contract inside another contract which is assigned to a variable.
abi.encodeWithSignature("execute(bytes)", _data, _gasLimit)

action function task: turn one statement into two independent statements.first statement is the variable part which is supposed to ba boolean and we assign "true" value to cover any kind of usage of that variable and possible business logic.
second statement would be the function call without caring about its return value. actually we assume that the function call return a boolean value. in this way we create a vulnerable contract due to not checking the return value of that specific function call.
abi.encodeWithSignature("execute(bytes)", _data)
'''

def condition(ast):
    matches = []

    def traverse(node):
        if isinstance(node, dict):
            # Check for the specific function call pattern
            if (node.get('nodeType') == 'FunctionCall' and 
                node.get('expression', {}).get('memberName') == 'encodeWithSignature' and
                len(node.get('arguments', [])) == 3):  # Looking for three arguments specifically
                matches.append(node)
            else:
                # Recursively search all child nodes
                for key, value in node.items():
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)

    traverse(ast)
    return matches

def condition11(ast):
    matches = []

    def traverse(node):
        # Check if the node is a dictionary and has the expected structure
        if isinstance(node, dict):
            # Check for the specific function call pattern
            if (node.get('nodeType') == 'FunctionCall' and
                node.get('expression', {}).get('memberName') == 'encodeWithSignature' and
                'arguments' in node and len(node['arguments']) == 3):
                matches.append(node)
                # Ensure the first argument is the correct function signature string
                #first_arg = node['arguments'][0]
                #if isinstance(first_arg, dict) and first_arg.get('value') == "execute(bytes)":
                    # Additional checks for other arguments could be added here if necessary
                    #matches.append(node)

            # Recursively search all child nodes
            for key, value in node.items():
                if isinstance(value, (list, dict)):
                    traverse(value)

        elif isinstance(node, list):
            for item in node:
                traverse(item)

    traverse(ast)
    return matches

def action(ast, target_node):
    operation_type = None
    modified_node = target_node.copy()  # Deep copy may be needed for complex structures

    # Modify the node by removing the third parameter
    if len(modified_node['arguments']) == 3:
        modified_node['arguments'] = modified_node['arguments'][:2]  # Keep only the first two parameters

    return [modified_node], operation_type


if __name__ == "__main__":
    mainfunc('3-1', condition, action, '3-1')