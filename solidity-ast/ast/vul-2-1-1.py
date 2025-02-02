#!/usr/bin/env python3

from common import mainfunc

'''
ver_2
Vulnerability: 2.1.1 Improper Use of Exception Handling Functions source: https://openscv.dei.uc.pt/

condition function task: identify any function call of specific contract inside another contract which is assigned to a variable.
msg.sender.call.value(amount)("")

action function task: turn one statement into two independent statements.first statement is the variable part which is supposed to ba boolean and we assign "true" value to cover any kind of usage of that variable and possible business logic.
second statement would be the function call without caring about its return value. actually we assume that the function call return a boolean value. in this way we create a vulnerable contract due to not checking the return value of that specific function call.
msg.sender.transfer(amount)
'''

def is_target_call_value(nodee):
    if nodee.get('nodeType') == "VariableDeclarationStatement":
        node = nodee.get('initialValue')
        if node is not None and node.get('nodeType') == "FunctionCall":
            outer_expression = node.get('expression')
            if outer_expression.get('expression') is None:
                return False
            outer_expression2 = outer_expression.get('expression')
            if outer_expression2.get('nodeType') == 'MemberAccess' and outer_expression2.get('memberName') == 'value':
                call_expression = outer_expression2.get('expression')
                if call_expression.get('nodeType') == 'MemberAccess' and call_expression.get('memberName') == 'call':
                    sender_expression = call_expression.get('expression')
                    if sender_expression.get('nodeType') == 'MemberAccess' and sender_expression.get('memberName') == 'sender':
                        msg_expression = sender_expression.get('expression')
                        if msg_expression.get('nodeType') == 'Identifier' and msg_expression.get('name') == 'msg':
                            return True
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

    """
    Transforms a node representing 'msg.sender.call.value(amount)("")' into 'msg.sender.transfer(amount)'
    """

def action(ast, target_node):
    """
    Trasforma un nodo contenente '(bool success) = msg.sender.call.value(amount)("")'
    in due nodi distinti:
    - Uno per 'bool success = true'.
    - Uno per 'msg.sender.call.value(amount);' senza parentesi finali.
    """
    # Estrarre informazioni dal nodo target
    declarations = target_node.get('declarations', [])
    if not declarations or len(declarations) != 1:
        raise ValueError("Nodo non valido: manca la dichiarazione della variabile booleana.")

    # Modificare la dichiarazione booleana
    bool_declaration = declarations[0]
    bool_variable_name = bool_declaration['name']  # Nome della variabile (es. "success")

    # Nodo 1: Dichiarazione booleana (bool success = true)
    new_bool_statement = {
        "nodeType": "VariableDeclarationStatement",
        "assignments": [bool_declaration["id"]],
        "declarations": [bool_declaration],
        "initialValue": {
            "nodeType": "Literal",
            "kind": "bool",
            "value": "true",
            "typeDescriptions": {
                "typeIdentifier": "t_bool",
                "typeString": "bool"
            },
            "src": target_node["src"]  # Riutilizza la posizione sorgente
        },
        "src": target_node["src"]
    }

    # Nodo 2: Chiamata a msg.sender.call.value(amount);
    original_function_call = target_node.get("initialValue", {})
    new_call_statement = {
        "nodeType": "ExpressionStatement",
        "expression": {
            "nodeType": "FunctionCall",
            "expression": original_function_call.get("expression"),
            "arguments": [],  # Usa una lista vuota per rappresentare l'assenza di argomenti
            "kind": original_function_call.get("kind"),
            "src": original_function_call["src"],
            "typeDescriptions": original_function_call.get("typeDescriptions")
        },
        "src": original_function_call["src"]
    }


    # Ritornare i due nodi come nuova struttura
    return [new_bool_statement, new_call_statement], None

if __name__ == "__main__":
    mainfunc('2-1-1', condition, action, '2-1-1')