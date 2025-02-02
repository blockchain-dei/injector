#!/usr/bin/env python3

from common import mainfunc

'''
Vulnerability 3-2: Hardcoded Gas Amount in Calls
Source: https://openscv.dei.uc.pt/

condition function task: Identifies any usage of `.call`, `.send`, or `.transfer` with a hardcoded gas amount.

action function task: Modifies the gas amount to a fixed value (e.g., 2300) to introduce a vulnerability to gas limit changes.
'''

def condition(ast):

    matches = []

    def traverse(node):
        if isinstance(node, dict):
            # Verifica se il nodo è una funzione di tipo 'call', 'send', o 'transfer'
            if node.get("nodeType") == "FunctionCall":
                expression = node.get("expression", {})
                member_name = expression.get("expression", {}).get("memberName")
                
                if member_name in ["call", "send", "transfer"]:
                    if expression.get("nodeType") == "FunctionCallOptions":
                    # Trova se c'è un parametro 'gas' hardcoded
                        options = node.get("expression", {}).get("options", [])
                        for option in options:
                            if isinstance(option, dict) and option.get("nodeType") == "Literal" and option.get("kind") == "number":
                                gas_value = option.get("value")
                                # Verifica se il valore di gas è hardcoded
                                if gas_value == "2300":  # oppure un altro valore fisso
                                    matches.append(node)
                                
                                    
            
            # Ricorsione sui figli del nodo
            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)

    traverse(ast)
    print(f"Matches found: {matches}")
    return matches


def action(ast, target_node):
    """
    Modifies a function call to set a fixed gas amount (e.g., 2300).
    """
    operation_type = None
    modified_node = target_node.copy()

    # Set gas amount to 2300
    modified_node["expression"]["arguments"] = [{"nodeType": "Literal", "value": "2300", "kind": "number"}]

    return [modified_node], operation_type


if __name__ == "__main__":
    mainfunc('3-2', condition, action, '3-2')
