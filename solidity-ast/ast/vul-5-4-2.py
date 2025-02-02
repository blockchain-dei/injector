#!/usr/bin/env python3

from common import mainfunc
import copy, json

'''
Vulnerability: 5.4.2  Wrong Selection of Guard Function source: https://openscv.dei.uc.pt/

condition function task: identify any function call of specific contract inside another contract which call "require" function.

action function task: turn one statement into two independent statements.first statement is the variable part which is supposed to ba boolean and we assign "true" value to cover any kind of usage of that variable and possible business logic.
second statement would be the function call without caring about its return value. actually we assume that the function call return a boolean value. in this way we create a vulnerable contract due to not checking the return value of that specific function call.
'''

def condition(ast):
    
    vulnerabilities = []

    def traverse(node):
        
        if isinstance(node, dict):
            
            if node.get("nodeType") == "FunctionCall" and node.get("arguments", []):
                exp = node.get("expression", {})
                if exp and exp.get("name") == "require" and exp.get("nodeType") == "Identifier":
                    vulnerabilities.append(node)

            for value in node.values():
                if isinstance(value, (dict, list)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast)

    return vulnerabilities

def action(ast, target_node):
    
    operation_type = None

    target_node['expression']['overloadedDeclarations'] = []
    target_node['expression']['argumentTypes'] = [
        {
            "typeIdentifier": "t_bool",
            "typeString": "bool"
        }
    ]
    target_node['expression']['typeDescriptions'] = {
        "typeIdentifier": "t_function_assert_pure$_t_bool_$returns$__$",
        "typeString": "function (bool) pure"
    }
    target_node['expression']['name'] = "assert"
    napoli = target_node['arguments'][0]
    target_node['arguments'] = [napoli]

    return target_node, operation_type

if __name__ == "__main__":
    mainfunc('5-4-2', condition, action, '5-4-2')
