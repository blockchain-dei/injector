#!/usr/bin/env python3

from common import mainfunc

'''
Vulnerability: 1.1.1 Unsafe Credit Transfer
source: https://openscv.dei.uc.pt/

Condition: looking for a function with a "Checks-Effects-Interations" patter, in according with solidity standard every function
shouldn't vulnerable so need to follow a specific flow, ex: burn a transfer 
    1) Check if there are enought credits
    2) Decrement the available creditss befor the transfer, in this way a reentrancy attack is useless
    3) Actually trasfer the credits
Assumptions: the "C-E-I" pattern follows three standards procedure
    +require statement
    +decrement of the credits
    +trasmission of an event

Action: move the trasmission of the event as the first statement of the block inside the function definition, so if in some way
the attacker execute a reentrancy attack it can consume all the credit available

'''


def condition(ast):

    vulnerable_nodes = []

    def traverse(node):
        if isinstance(node, dict):
            if node.get("nodeType") == "FunctionDefinition" and node.get("body"):
                body = node["body"].get("statements", [])
                
                has_require = False
                has_state_change = False
                has_event_emission = False
                
                for statement in body:
                    if statement.get("nodeType") == "ExpressionStatement":
                        expression = statement.get("expression", {})
                        #doesn't match burn because this one haven't a name ("name": [])
                        #if expression.get("nodeType") == "FunctionCall" and expression.get("expression", {}).get("name") == "require":
                        if expression.get("nodeType") == "FunctionCall" and expression.get("expression", {}).get("typeDescriptions").get("typeIdentifier") == "t_function_require_pure$_t_bool_$returns$__$":
                            has_require = True
                        
                        elif has_require and expression.get("nodeType") == "Assignment":
                            left = expression.get("leftHandSide", {})
                            
                            if left.get("nodeType") == "IndexAccess":
                                base = left.get("baseExpression", {})
                                index = left.get("indexExpression", {})
                                
                                if base.get("name") == "balances" and index.get("name") == "_from":
                                    has_state_change = True
                    
                    if has_require and has_state_change and statement.get("nodeType") == "EmitStatement":
                        has_event_emission = True
                
                if has_require and has_state_change and has_event_emission:
                    vulnerable_nodes.append(node)
                    return

            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    traverse(value)

        elif isinstance(node, list):
            for item in node:
                traverse(item)

    traverse(ast)
    return vulnerable_nodes



def action(ast, target_node):

    function_body = target_node.get("body", {}).get("statements", [])
    
    emit_index = None
    for i, statement in enumerate(function_body):
        if statement.get("nodeType") == "EmitStatement":
            emit_index = i
            break

    if emit_index is not None:
        emit_statement = function_body.pop(emit_index)
        function_body.insert(0, emit_statement)
        target_node["body"]["statements"] = function_body
        print(f"Moved 'emit' statement to the beginning of function '{target_node.get('name', 'unknown')}'")

    operation_type = None

    return [target_node], operation_type


if __name__ == "__main__":
    mainfunc('1-1-1.', condition, action, '1-1-1')