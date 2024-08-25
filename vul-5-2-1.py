#!/usr/bin/env python3

from commonc import mainfunc
import copy

'''
Vulnerability: 5.2.1 Missing Constructor source: https://openscv.dei.uc.pt/

condition function task: identify any function call of specific contract inside another contract which is assigned to a variable.

action function task: turn one statement into two independent statements.first statement is the variable part which is supposed to ba boolean and we assign "true" value to cover any kind of usage of that variable and possible business logic.
second statement would be the function call without caring about its return value. actually we assume that the function call return a boolean value. in this way we create a vulnerable contract due to not checking the return value of that specific function call.
'''

def condition(ast):
    constructors = []

    def traverse(node):
        if isinstance(node, dict):
            # Check for constructor definition
            if node.get('nodeType') == 'FunctionDefinition':
            	if node.get('kind') == 'constructor' or node.get('isConstructor', False):
                	constructors.append(node)
                	print(f"condition-constructor-node: {node['id']}\n")
            # Traverse through all children of the node
            for key in node:
                traverse(node[key])
        elif isinstance(node, list):
            for item in node:
                traverse(item)

    traverse(ast)
    return constructors


def action(ast, constructor_node):
    # For removing a constructor, we return an empty list indicating no replacement
    operation_type = None
    return [], operation_type


if __name__ == "__main__":
    mainfunc('5-2-1', condition, action, '5-2-1')