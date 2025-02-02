#!/usr/bin/env python3

from common import mainfunc

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


def action(ast, target_node):
    operation_type = None
    modified_node = target_node.copy()  # Deep copy may be needed for complex structures

    # Modify the node by removing the third parameter
    if len(modified_node['arguments']) == 3:
        modified_node['arguments'] = modified_node['arguments'][:2]  # Keep only the first two parameters

    return [modified_node], operation_type


if __name__ == "__main__":
    mainfunc('3-1', condition, action, '3-1')