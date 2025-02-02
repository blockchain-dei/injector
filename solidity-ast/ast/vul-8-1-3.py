#!/usr/bin/env python3

import copy
from common import mainfunc

'''
Vulnerability: 8.1.3 Missing verification for program termination source: https://openscv.dei.uc.pt/

condition: find a function in wich there is at least a require node

action: delete all require node

'''

def condition(ast):

    vulnerable_functions = []

    def traverse(node):
        if isinstance(node, dict):
            nodeType = node.get("nodeType")
            
            if nodeType == "FunctionDefinition":
                _require = False
                _destruction = False
                
                if node.get("body") is not None:
                    body = node.get("body", {}).get("statements", [])
                else:
                    exit
                
                for statement in body:
                    if statement.get("nodeType") == "ExpressionStatement":
                        expression = statement.get("expression", {})

                        if expression.get("nodeType") == "FunctionCall" and expression.get("expression", {}).get("name") == "require":
                            _require = True
                        
                        if expression.get("nodeType") == "FunctionCall" and expression.get("expression", {}).get("name") == "selfdestruct":
                            _destruction = True

                    if _require and _destruction:
                        vulnerable_functions.append(node)
                        break
            else:
                for value in node.values():
                    if isinstance(value, (dict, list)):
                        traverse(value)
        elif isinstance(node, list):
            for item in node:
                if isinstance(item, (dict, list)):
                    traverse(item)

    traverse(ast)
    return vulnerable_functions

def action(ast, target_node):

    operation_type = None
    body = target_node.get("body", {}).get("statements", [])
    new_body = []

    for node in body:
        if not (node.get("nodeType") == "ExpressionStatement" and 
            node.get("expression", {}).get("nodeType") == "FunctionCall" and 
            node.get("expression", {}).get("expression", {}).get("name") == "require"):
            new_body.append(node)

    target_node["body"]["statements"] = new_body

    return [target_node], operation_type

def action2(ast, target_function):

    operation_type = None

    # Crea una copia dell'AST
    _ast = copy.deepcopy(ast)

    # Trova e modifica la funzione 'destroy'
    for node in _ast.get("nodes", []):
        if node.get("nodeType") == "FunctionDefinition" and node.get("name") == "destroy":
            # Cerca il nodo del body e rimuove il require
            body = node.get("body", {}).get("statements", [])
            new_body = []

            for statement in body:
                # Esclude il nodo `require`
                if not (statement.get("nodeType") == "ExpressionStatement" and 
                        statement.get("expression", {}).get("nodeType") == "FunctionCall" and 
                        statement.get("expression", {}).get("expression", {}).get("name") == "require"):
                    new_body.append(statement)
            
            # Sostituisci il body con il nuovo body
            node["body"]["statements"] = new_body

    return _ast, operation_type

if __name__ == "__main__":
    mainfunc('8-1-3', condition, action, '8-1-3')
