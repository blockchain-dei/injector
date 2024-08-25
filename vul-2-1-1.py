#!/usr/bin/env python3

from commonc import mainfunc

'''
Vulnerability: 2.1.1 Improper Use of Exception Handling Functions source: https://openscv.dei.uc.pt/

condition function task: identify any function call of specific contract inside another contract which is assigned to a variable.
msg.sender.call.value(amount)("")

action function task: turn one statement into two independent statements.first statement is the variable part which is supposed to ba boolean and we assign "true" value to cover any kind of usage of that variable and possible business logic.
second statement would be the function call without caring about its return value. actually we assume that the function call return a boolean value. in this way we create a vulnerable contract due to not checking the return value of that specific function call.
msg.sender.transfer(amount)
'''

def is_target_FunctionCallOptions11(node):
    # First, check if the node is a FunctionCallOptions node with 'call' as a memberName in its expression chain
    #print(f"option-node: {node}\n")
    #initialValue = node.get('initialValue')
    #print(f"option-initialValue: {initialValue}\n")
    if 'expression' in node and node.get('expression') is not None:
    	childNode = node.get('expression')
    	#print(f"option-childNode: {childNode}\n")
    	if childNode.get('nodeType') == 'FunctionCallOptions':
    		expression = childNode.get('expression')
    		while expression:
    			# Check if we have reached a MemberAccess node with 'call'
    			if expression.get('nodeType') == 'MemberAccess' and expression.get('memberName') == 'call':
    				return True
    			# Move to the next nested expression
    			expression = expression.get('expression')
    return False

def condition11(ast):
    matches = []

    def traverse(node, parent=None):
        if isinstance(node, dict):
            #print(f"1\n")
            if is_target_FunctionCallOptions(node) and \
               	'msg' in str(node.get('expression', {}).get('expression', {}).get('expression', {})):
               	# Check if this node is part of an assignment
               	print(f"4\n")
               	if parent and parent.get('nodeType') == 'VariableDeclarationStatement':
               		print(f"5\n")
               		matches.append(parent)
            for key, value in node.items():
                traverse(value, node)
        elif isinstance(node, list):
            for item in node:
                traverse(item, parent)

    traverse(ast)
    return matches

def is_target_call_value(node):
    if node.get('nodeType') == 'FunctionCall':
        # Check the outer function call (should be `.call(...)`)
        #print(f"is_target_call_value-1\n")
        #if node.get('id') != 110:
        	#return False
        print(f"is_target_call_value-1111\n")
        outer_expression = node.get('expression')
        print(f"is_target_call_value-outer_expression: {outer_expression}\n")
        if outer_expression.get('expression') is None:
        	return False
        outer_expression2 = outer_expression.get('expression')
        print(f"is_target_call_value-outer_expression2: {outer_expression2}\n")
        if outer_expression2.get('nodeType') == 'MemberAccess' and outer_expression2.get('memberName') == 'value':
            # Check the sender (should be `msg.sender`)
            print(f"is_target_call_value-2\n")
            call_expression = outer_expression2.get('expression')
            if call_expression.get('nodeType') == 'MemberAccess' and call_expression.get('memberName') == 'call':
                print(f"is_target_call_value-3\n")
                sender_expression = call_expression.get('expression')
                if sender_expression.get('nodeType') == 'MemberAccess' and sender_expression.get('memberName') == 'sender':
                	print(f"is_target_call_value-4\n")
                	msg_expression = sender_expression.get('expression')
                	if msg_expression.get('nodeType') == 'Identifier' and msg_expression.get('name') == 'msg':
                		print(f"is_target_call_value-5\n")
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
    
def is_target_function_callold(node):
    # First, check if the node is a FunctionCallOptions node with 'call' as a memberName in its expression chain
    if node.get('nodeType') == 'FunctionCallOptions':
        expression = node.get('expression')
        while expression:
            # Check if we have reached a MemberAccess node with 'call'
            if expression.get('nodeType') == 'MemberAccess' and expression.get('memberName') == 'call':
                return True
            # Move to the next nested expression
            expression = expression.get('expression')
    return False

def conditionold(ast):
    matches = []

    def traverse(node, parent=None):
        if isinstance(node, dict):
            if is_target_function_call(node) and \
                'msg' in str(node.get('expression', {}).get('expression', {}).get('expression', {})):
                # Check if this node is part of an assignment
                if parent and parent.get('nodeType') == 'VariableDeclarationStatement':
                    matches.append(parent)
            for key, value in node.items():
                traverse(value, node)
        elif isinstance(node, list):
            for item in node:
                traverse(item, parent)

    traverse(ast)
    return matches


def conditionold2(ast):
    """
    Searches the AST for expressions that match known vulnerable patterns
    and are part of an assignment, specifically focusing on msg.sender.call patterns.
    """
    matches = []

    def traverse(node, parent=None):
        # Base case: if node is a dict, check for expression matches
        if isinstance(node, dict):
            # Check if the node is a FunctionCall within a VariableDeclarationStatement (part of an assignment)
            print(f"1\n")
            if node.get('id') == 38:
                print(f"11\n")
                if node.get('expression', {}).get('memberName') == 'call':
                	print(f"112\n")
                if node.get('nodeType') == 'FunctionCall':
                	print(f"113\n")
                if 'msg' in str(node.get('expression', {}).get('expression', {}).get('expression', {})):
                	print(f"114\n")
            if node.get('nodeType') == 'FunctionCall' and node.get('expression', {}).get('memberName') == 'call' and \
                'msg' in str(node.get('expression', {}).get('expression', {}).get('expression', {})):
                # Additional check for 'value' option in FunctionCallOptions to match the known expression
                print(f"2\n")
                if any(option for option in node.get('options', []) if option.get('name') == 'value'):
                    print(f"3\n")
                    if parent and parent.get('nodeType') == 'VariableDeclarationStatement':
                        print(f"4\n")
                        matches.append(parent)  # Append the assignment statement, not just the call expression
                
            # Recursive case: Traverse through all child nodes
            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    traverse(value, node)
                    
        elif isinstance(node, list):
            # Recursively search in all list items
            for item in node:
                traverse(item, parent)

    traverse(ast)
    return matches

def conditionold(ast):
    """
    Searches the AST for expressions with vulstatus=0 that match known vulnerable patterns
    and are used on the right-hand side of an assignment.
    """
    matches = []

    def is_vulnerable_expr_used_in_assignment(expr, node):
        # Simplified check for the usage of expr in the right-hand side of an assignment
        # This logic may need to be more complex depending on the exact AST structure of your expressions
        return expr['full_name'] in str(node.get('rightHandSide', ''))

    def traverse(node, parent=None):
        if isinstance(node, dict):
            # Iterate only over expressions with "vulstatus": 0
            print(f"1\n")
            for expr in filter(lambda e: e['vulstatus'] == 0, known_expressions):
                # Check for FunctionCall nodes that match the known expression and are part of an assignment
                if node.get('id') == 38:
                	print(f"2:{str(node)}\n")
                print(f"2:{expr['full_name']}\n")
                if node.get('nodeType') == 'FunctionCall' and expr['full_name'] in str(node):
                    # Ensure this node is the right-hand side of an assignment
                    print(f"3\n")
                    if parent and parent.get('nodeType') == 'Assignment' and is_vulnerable_expr_used_in_assignment(expr, parent):
                        print(f"4\n")
                        matches.append((node, parent, expr))
            
            # Recursively search in all dictionary values
            for key, value in node.items():
                traverse(value, node)

        elif isinstance(node, list):
            for item in node:
                traverse(item, parent)

    traverse(ast)
    print(f"condition-matches: {matches}\n")
    return matches


def action(ast, target_node):
    """
    Transforms a node representing 'msg.sender.call.value(amount)("")' into 'msg.sender.transfer(amount)'
    """
    operation_type = None
    # First, let's extract the amount which is used in the call.value(amount)
    amount_argument = None
    if target_node.get('nodeType') == 'FunctionCall':
    	arguments = target_node.get('expression', {}).get('arguments', {})
    	amount_argument = arguments[0]

    if amount_argument is None:
        raise ValueError("No valid 'amount' argument found for .value()")

    # Now, construct the new node for msg.sender.transfer(amount)
    new_function_call = {
        "nodeType": "FunctionCall",
        "expression": {
            "nodeType": "MemberAccess",
            "expression": {
                "nodeType": "MemberAccess",
                "expression": {
                    "nodeType": "Identifier",
                    "name": "msg"
                },
                "memberName": "sender",
                "typeDescriptions": {
                    "typeIdentifier": "t_address_payable",
                    "typeString": "address payable"
                }
            },
            "memberName": "transfer",
            "typeDescriptions": {
                "typeIdentifier": "t_function_transfer_nonpayable$_t_uint256_$returns$_t_bool_$",
                "typeString": "function (uint256) returns (bool)"
            }
        },
        "arguments": [amount_argument],
        "typeDescriptions": {
            "typeIdentifier": "t_bool",
            "typeString": "bool"
        },
        "src": target_node.get('src'),  # Optionally reuse the source location from the original call
    }

    # Assuming the target_node was inside an ExpressionStatement
    new_expression_statement = {
        "nodeType": "ExpressionStatement",
        "expression": new_function_call,
        "src": target_node.get('src')  # Reuse the source location if applicable
    }

    # Replace the original node in the AST (this step depends on the structure of your AST and how you manage it)
    # For this example, let's just return the new node
    return new_function_call, operation_type
    
def action11(ast, target_node):
    """
    Creates a list of nodes representing the transformation:
    1. Declaring and assigning 'success' to true (mimicking '(bool success) = true;').
    2. Calling 'msg.sender.transfer(amount);'
    """
    operation_type = None
    # Assuming 'amount' argument extraction as previously shown
    amount_argument = None
    if "value" in target_node['initialValue']['expression']['names']:
        amount_argument = target_node['initialValue']['expression']['options'][0]

    if amount_argument is None:
        print("Error: 'amount' argument could not be extracted.")
        return []

    # Mimicking '(bool success) = true;' by a variable declaration with immediate assignment
    success_declaration_node = {
        "nodeType": "VariableDeclarationStatement",
        "declarations": [{
            "nodeType": "VariableDeclaration",
            "typeName": {
                "nodeType": "ElementaryTypeName",
                "name": "bool"
            },
            "name": "success",
        }],
        "initialValue": {
            "nodeType": "Literal",
            "value": "true",
            "kind": "bool"
        }
    }

    # Construct the transfer call node
    transfer_call_node = {
        "nodeType": "ExpressionStatement",
        "expression": {
            "nodeType": "FunctionCall",
            "expression": {
                "nodeType": "MemberAccess",
                "expression": {
                    "nodeType": "Identifier",
                    "name": "msg.sender"
                },
                "memberName": "transfer"
            },
            "arguments": [{
                "nodeType": "Identifier",
                "name": amount_argument['name']
            }]
        }
    }

    # Return the new nodes as a list
    return [success_declaration_node, transfer_call_node], operation_type

def actionold3(ast, target_node):
    """
    Adjusts the action to replace a vulnerable pattern with a variable assignment to true and a transfer call,
    taking into account the correct structure of the AST for the call options.
    
    :param ast: The entire AST of the smart contract.
    :param target_node: The node identified by the condition function as vulnerable.
    :return: A list of nodes that replace the vulnerable pattern with an assignment to true and a transfer call.
    """
    # Initialize amount_argument with None
    amount_argument = None
    
    # Check if 'value' is mentioned in the names of the FunctionCallOptions
    if "value" in target_node['initialValue']['expression']['names']:
        # Assuming 'value' corresponds to the first option when it's present
        amount_argument = target_node['initialValue']['expression']['options'][0]
    
    # Validate extraction of the 'amount' argument
    if amount_argument is None:
        print("Error: 'amount' argument could not be extracted.")
        return []

    # Construct the transfer call node
    transfer_call_node = {
        "nodeType": "ExpressionStatement",
        "expression": {
            "nodeType": "FunctionCall",
            "expression": {
                "nodeType": "MemberAccess",
                "expression": {
                    "nodeType": "Identifier",
                    "name": "msg.sender"
                },
                "memberName": "transfer"
            },
            "arguments": [{
                "nodeType": "Identifier",
                "name": amount_argument['name']
            }]
        }
    }

    # Construct the variable assignment to true
    variable_assignment_node = {
        "nodeType": "ExpressionStatement",
        "expression": {
            "nodeType": "Assignment",
            "operator": "=",
            "leftHandSide": {
                "nodeType": "Identifier",
                "name": "success"
            },
            "rightHandSide": {
                "nodeType": "Literal",
                "value": "true",
                "kind": "bool"
            }
        }
    }

    # Return the new nodes as a list
    return [variable_assignment_node, transfer_call_node]

def actionold2(ast, target_node):
    """
    Adjusts the action to replace a vulnerable pattern with a variable assignment to true and a transfer call.
    Correctly handles extraction of the 'amount' argument from the call options.

    :param ast: The entire AST of the smart contract.
    :param target_node: The node identified by the condition function as vulnerable.
    :return: A list of nodes that replace the vulnerable pattern with an assignment to true and a transfer call.
    """
    # Initialize amount_argument with a default value
    amount_argument = None

    print(f"action-node: {target_node}")
    # Attempt to extract the 'amount' argument from the call options
    for exprr in target_node['initialValue']['expression']:
        if exprr.get('names') == 'value':
            amount_argument = exprr.get('option')[0]

    # Check if the amount argument was successfully extracted
    if amount_argument is None:
        print("Error: 'amount' argument could not be extracted.")
        return []

    transfer_call_node = {
        "nodeType": "ExpressionStatement",
        "expression": {
            "nodeType": "FunctionCall",
            "expression": {
                "nodeType": "MemberAccess",
                "expression": {
                    "nodeType": "Identifier",
                    "name": "msg.sender"
                },
                "memberName": "transfer"
            },
            "arguments": [{
                "nodeType": "Identifier",
                "name": amount_argument['name']
            }]
        }
    }

    variable_declaration_node = {
        "nodeType": "VariableDeclarationStatement",
        "declarations": [{
            "nodeType": "VariableDeclaration",
            "typeName": {
                "nodeType": "ElementaryTypeName",
                "name": "bool"
            },
            "name": "success"
        }],
        "initialValue": {
            "nodeType": "Literal",
            "value": "true",
            "kind": "bool"
        }
    }

    new_nodes = [variable_declaration_node, transfer_call_node]

    return new_nodes


def actionold(ast, target_node):
    """
    Constructs a safer alternative for a vulnerable call found by the condition function.

    :param ast: The entire AST of the smart contract.
    :param target_node: The node identified by the condition function as vulnerable.
    :return: A list of nodes that replace the vulnerable call with a safer alternative.
    """
    # Extract necessary information from the target_node
    # Assuming target_node is the VariableDeclarationStatement node encompassing the vulnerable call
    variable_name = target_node['declarations'][0]['name']
    amount_argument = None

    # Extract the amount argument from the call options
    for option in target_node['initialValue']['expression']['options']:
        if option.get('name') == 'value':
            amount_argument = option

    # Create the transfer call node
    transfer_call_node = {
        "nodeType": "ExpressionStatement",
        "expression": {
            "nodeType": "FunctionCall",
            "expression": {
                "nodeType": "MemberAccess",
                "expression": target_node['initialValue']['expression']['expression']['expression'],
                "memberName": "transfer"
            },
            "arguments": [amount_argument] if amount_argument else []
        }
    }

    # Create an assignment to true for the success variable, if it exists
    assignment_to_true_node = None
    if variable_name:
        assignment_to_true_node = {
            "nodeType": "ExpressionStatement",
            "expression": {
                "nodeType": "Assignment",
                "operator": "=",
                "leftHandSide": {
                    "nodeType": "Identifier",
                    "name": variable_name
                },
                "rightHandSide": {
                    "nodeType": "Literal",
                    "value": "true",
                    "kind": "bool"
                }
            }
        }

    # Return a list of the new nodes to replace the vulnerable pattern
    new_nodes = [transfer_call_node]
    if assignment_to_true_node:
        new_nodes.insert(0, assignment_to_true_node)  # Insert assignment before the transfer call

    return new_nodes

def actionold(ast, target_node):
    """
    Replaces a target expression with its corresponding vulnerable expression and constructs
    a new call node based on the vulnerable expression's specification.
    """
    # Retrieve the original expression's linked vulnerable expression
    print(f"\naction-target_node: {target_node}\n")
    print(f"\naction-target_node0: {target_node[0]}\n")
    print(f"\naction-target_node1: {target_node[1]}\n")
    print(f"\naction-target_node2: {target_node[2]}\n")
    original_expr = target_node[2]  # Assuming target_node format is (node, parent, expr)
    vulnerable_expr = known_expressions[original_expr['linkageIndex']]
    
    # Initialize a new call node structure
    call_node = {
        "nodeType": "ExpressionStatement",
        "expression": {}
    }
    
    # Update the call_node expression if the linked vulnerable expression has vulstatus == 1
    if vulnerable_expr['vulstatus'] == 1:
        # Construct the new expression based on vulnerable_expr specifications
        # This is a simplified version, you may need to adjust it based on your known_expressions structure
        call_node['expression'] = {
            "nodeType": "FunctionCall",
            "expression": {
                "nodeType": "MemberAccess",
                "expression": {
                    "nodeType": "Identifier",
                    "name": vulnerable_expr['base']  # Assuming structure contains base like 'msg.sender'
                },
                "memberName": vulnerable_expr['functionName']  # Assuming structure contains functionName
            },
            "arguments": []  # You may need to fill this based on vulnerable_expr specifications
        }
        
        # Example of adding arguments based on the known_expressions entry
        # This is highly dependent on how your expressions and arguments are structured
        for arg_type, arg_value in zip(vulnerable_expr['input_parameters'], target_node[0]['arguments']):
            call_node['expression']['arguments'].append({
                # You might need a more complex structure depending on argument types and values
                "nodeType": "Literal" if arg_type == 'literal' else "Identifier",
                "value": arg_value if arg_type == 'literal' else None,
                "name": arg_value if arg_type != 'literal' else None,
                "typeDescriptions": {
                    "typeString": arg_type
                }
            })
    
    # Assuming the action function needs to return a modified node list
    modified_nodes = [call_node]
    return modified_nodes


def actionold(ast, match):
    """
    Constructs a list of nodes representing the vulnerable code transformation.
    """
    # Extract the matched node, its parent, and the expression details
    node, parent, expr = match
    modified_nodes = []

    # Depending on the expression, modify the AST nodes accordingly
    if expr['vulstatus'] == 0:  # Normal expression, needs to be made vulnerable
        # Step 1: Change the call expression
        vulnerable_expr = known_expressions[expr['linkageIndex']]
        # This step assumes we can directly replace the call with the vulnerable version
        # You'll need to adjust the node details to match the structure of `vulnerable_expr`
        call_node = {
            "nodeType": "ExpressionStatement",
            "expression": {
                # Placeholder for the new call expression structure
            }
        }

        # Step 2: Split the assignment into two statements if necessary
        assignment_node = {
            "nodeType": "ExpressionStatement",
            "expression": {
                "nodeType": "Assignment",
                "operator": "=",
                "leftHandSide": parent['leftHandSide'],
                "rightHandSide": {
                    "nodeType": "Literal",
                    "value": "true",
                    "typeDescriptions": {
                        "typeIdentifier": "t_bool",
                        "typeString": "bool"
                    }
                }
            }
        }

        modified_nodes.extend([call_node, assignment_node])

    return modified_nodes

known_expressions = [
    {
        "full_name": "msg.sender.call",
        "input_parameters": ["uint256", "string"],
        "input_parameters_optional_indexes": [0, 1],
        "output_type": "bool",
        "vulstatus": 0,
        "linkageIndex": 1
    },
    {
        "full_name": "msg.sender.transfer",
        "input_parameters": ["uint256"],
        "input_parameters_optional_indexes": [0],
        "output_type": None,
        "vulstatus": 1,
        "linkageIndex": 0
    }
]

if __name__ == "__main__":
    mainfunc('2-1-1', condition, action, '2-1-1')