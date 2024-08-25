#!/usr/bin/env python3

from commonc import mainfunc

'''
Vulnerability: 4.1 Improper Check on Transfer Credit source: https://openscv.dei.uc.pt/

condition function task: bool b = msg.sender.send(bal[msg.sender]);

action function task: 
bool b = true;
msg.sender.send(balances[msg.sender]);
'''

def conditionnew(ast):
    matches = []

    def is_msg_sender_involved(argument):
        # Check if 'msg.sender' is directly used or wrapped in 'payable'
        if 'msg.sender' in str(argument):
            return True
        # Additional checks can be added here for more complex structures if needed
        return False

    def traverse(node, parent=None):
        if isinstance(node, dict):
            nodeType = node.get('nodeType')
            # Check if the node is a function call to 'send'
            if nodeType == 'FunctionCall' and node.get('expression', {}).get('memberName') == 'send':
                arguments = node.get('arguments', [])
                # Check each argument for 'msg.sender' or 'payable(msg.sender)'
                for argument in arguments:
                    if is_msg_sender_involved(argument):
                        # Check if this function call is part of an assignment's right side
                        if parent and parent.get('nodeType') == 'Assignment':
                            matches.append(parent)
                        break
            # Traverse through children nodes, passing current node as parent
            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    traverse(value, node)
        elif isinstance(node, list):
            # If it's a list, traverse through each item
            for item in node:
                traverse(item, parent)

    # Start traversing from the root of the AST
    traverse(ast)
    return matches

def condition(ast):
    matches = []

    def traverse(node, parent=None):
        # Check if the current node is a function call
        if (isinstance(node, dict) and
            node.get('nodeType') == 'FunctionCall' and
            node.get('expression', {}).get('nodeType') == 'MemberAccess' and
            node['expression'].get('memberName') == 'send'):
            #print(f"condition-node: {node}\n")
            #print(f"condition: 1\n")
            # Extract the expression for further checks
            expression = node.get('expression', {}).get('expression', {})
            # Check for direct usage of msg.sender
           # print(f"condition-expression: {expression}\n")
            #print(f"condition-bool-1: {expression.get('expression', {}).get('nodeType', {}) == 'Identifier'}\n")
            #print(f"condition-bool-2: {expression.get('expression', {}).get('name', {}) == 'msg'}\n")
            #print(f"condition-bool-3: {expression.get('memberName', {}) == 'sender'}\n")
            direct_usage = (expression.get('expression', {}).get('nodeType', {}) == 'Identifier' and
                            expression.get('expression', {}).get('name', {}) == 'msg' and
                            expression.get('memberName', {}) == 'sender')
            #print(f"condition-direct_usage: {direct_usage}\n")
            # Check for usage of msg.sender wrapped in payable
            #wrapped_usage = (expression.get('nodeType') == 'FunctionCall' and
            #                 expression.get('expression', {}).get('nodeType') == 'ElementaryTypeNameExpression' and
            #                 'msg' in str(expression.get('arguments', {}).get('expression', {})) and
            #                 expression.get('expression', {}).get('typeName', {}).get('stateMutability') == 'payable')
            wrapped_usage = (expression.get('nodeType') == 'FunctionCall' and
                             expression.get('expression', {}).get('nodeType') == 'ElementaryTypeNameExpression' and
                             expression.get('expression', {}).get('typeName', {}).get('stateMutability') == 'payable')
            #print(f"condition-wrapped_usage: {wrapped_usage}\n")
            wrapped_usage_final = False;
            if wrapped_usage:
            	arguments = expression.get('arguments', [])
            	wrapped_usage_final = False;
            	for argument in arguments:
                    if argument.get('expression', {}).get('name') == 'msg':
                    	wrapped_usage_final = True;
            #print(f"condition-wrapped_usage_final: {wrapped_usage_final}\n")
            if direct_usage or wrapped_usage_final:
                # Ensure this function call is part of an assignment's right side
                #print(f"condition: 2\n")
                if parent and parent.get('nodeType') == 'VariableDeclarationStatement':
                    #print(f"condition: 3\n")
                    matches.append(parent)
			
        # Recursively traverse through child nodes
        if isinstance(node, dict):
            for value in node.values():
                traverse(value, node)
        elif isinstance(node, list):
            for item in node:
                traverse(item, parent)

    traverse(ast)
    return matches

def conditionold2(ast):
    matches = []

    def traverse(node, parent=None):
        # Check if the current node is a function call
        if (isinstance(node, dict) and
            node.get('nodeType') == 'FunctionCall' and
            node.get('expression', {}).get('nodeType') == 'MemberAccess' and
            node['expression'].get('memberName') == 'send'):
            print(f"condition-node: {node}\n")
            print(f"condition: 1\n")
            # Extract the expression for further checks
            expression = node.get('expression', {}).get('expression', {})
            # Check for direct usage of msg.sender
            print(f"condition-expression: {expression}\n")
            print(f"condition-bool-1: {expression.get('nodeType') == 'Identifier'}\n")
            print(f"condition-bool-2: {expression.get('name') == 'msg'}\n")
            print(f"condition-bool-3: {'sender' in str(node)}\n")
            direct_usage = (expression.get('nodeType') == 'Identifier' and
                            expression.get('name') == 'msg' and
                            'sender' in str(node))
            print(f"condition-direct_usage: {direct_usage}\n")
            # Check for usage of msg.sender wrapped in payable
            #wrapped_usage = (expression.get('nodeType') == 'FunctionCall' and
            #                 expression.get('expression', {}).get('nodeType') == 'ElementaryTypeNameExpression' and
            #                 'msg' in str(expression.get('arguments', {}).get('expression', {})) and
            #                 expression.get('expression', {}).get('typeName', {}).get('stateMutability') == 'payable')
            wrapped_usage = (expression.get('nodeType') == 'FunctionCall' and
                             expression.get('expression', {}).get('nodeType') == 'ElementaryTypeNameExpression' and
                             expression.get('expression', {}).get('typeName', {}).get('stateMutability') == 'payable')
            print(f"condition-wrapped_usage: {wrapped_usage}\n")
            wrapped_usage_final = False;
            if wrapped_usage:
            	arguments = expression.get('arguments', [])
            	wrapped_usage_final = False;
            	for argument in arguments:
                    if argument.get('expression', {}).get('name') == 'msg':
                    	wrapped_usage_final = True;
            print(f"condition-wrapped_usage_final: {wrapped_usage_final}\n")
            if direct_usage or wrapped_usage_final:
                # Ensure this function call is part of an assignment's right side
                if parent and parent.get('nodeType') == 'VariableDeclarationStatement':
                    matches.append(parent)
			
        # Recursively traverse through child nodes
        if isinstance(node, dict):
            for value in node.values():
                traverse(value, node)
        elif isinstance(node, list):
            for item in node:
                traverse(item, parent)

    traverse(ast)
    return matches

def conditionold(ast):
    matches = []

    def traverse(node, parent=None):
        # Check if the current node is a function call to msg.sender.send
        if (isinstance(node, dict) and
            node.get('nodeType') == 'FunctionCall' and
            node.get('expression', {}).get('nodeType') == 'MemberAccess' and
            node['expression'].get('memberName') == 'send' and
            'msg.sender' in str(node.get('expression', {}).get('expression', {}))):
            # Ensure this function call is part of an assignment's right side
            if parent and parent.get('nodeType') == 'Assignment':
                matches.append(parent)
        # Traverse through children nodes
        for value in node.values() if isinstance(node, dict) else []:
            traverse(value, node)

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

def actionold2(ast, target_node):
    modified_nodes = []

    # Extract the right-hand side of the assignment (the function call)
    print(f"action-target_node: {target_node}\n")
    function_call = target_node["initialValue"]
    expression = function_call["expression"]

    # Determine if the call is direct or wrapped in payable
    is_direct = expression.get('nodeType') == 'MemberAccess'
    is_wrapped = (expression.get('nodeType') == 'FunctionCall' and
                  expression.get('expression', {}).get('nodeType') == 'ElementaryTypeNameExpression')
    
    # Prepare the new assignment node (bool variable = true;)
    new_assignment = {
        "nodeType": "ExpressionStatement",
        "expression": {
            "nodeType": "Assignment",
            "operator": "=",
            "leftHandSide": target_node["leftHandSide"],
            "rightHandSide": {
                "nodeType": "Literal",
                "value": "true",
                "typeDescriptions": {
                    "typeString": "bool"
                }
            }
        }
    }
    
    # Prepare the new send call expression
    send_call = {
        "nodeType": "ExpressionStatement",
        "expression": function_call
    }
    if is_direct:
        # Direct usage: Use the expression as is
        send_call["expression"]["expression"] = expression
    elif is_wrapped:
        # Wrapped usage: Unwrap from payable
        send_call["expression"]["expression"] = expression["expression"]["arguments"][0]

    # Add the modified nodes
    modified_nodes.append(new_assignment)
    modified_nodes.append(send_call)

    return modified_nodes

def actionold(ast, target_node):
    # Extract the original function call from the target node
    function_call = target_node['rightHandSide']

    # Create a new variable declaration with a "true" literal value
    variable_declaration = {
        "nodeType": "VariableDeclarationStatement",
        "declarations": target_node['leftHandSide'],
        "initialValue": {
            "nodeType": "Literal",
            "value": "true",
            "typeDescriptions": {
                "typeIdentifier": "t_bool",
                "typeString": "bool"
            }
        }
    }

    # Update the original function call to a separate expression statement
    function_call_statement = {
        "nodeType": "ExpressionStatement",
        "expression": function_call
    }

    return [variable_declaration, function_call_statement]


if __name__ == "__main__":
    mainfunc('4-1', condition, action, '4-1')