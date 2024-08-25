#!/usr/bin/env python3

from commonc import mainfunc

'''
Vulnerability: 5.13.1 Stack-based Buffer Overflow source: https://openscv.dei.uc.pt/

condition function task: identify any function call of specific contract inside another contract which is assigned to a variable.

action function task: turn one statement into two independent statements.first statement is the variable part which is supposed to ba boolean and we assign "true" value to cover any kind of usage of that variable and possible business logic.
second statement would be the function call without caring about its return value. actually we assume that the function call return a boolean value. in this way we create a vulnerable contract due to not checking the return value of that specific function call.
'''

def condition(ast):
    """
    Identifies functions that are suitable for adding a recursive call.
    It returns functions that do not already contain a call to themselves.
    """
    suitable_functions = []
    
    def traverse(node, functionName=None):
    	if isinstance(node, dict):
    		nodeType = node.get("nodeType")
    		if nodeType == "FunctionDefinition":
    			#if node.get('isConstructor', False): #and node.get('kind') != 'constructor':
    			if 'isConstructor' in node and node['isConstructor'] is False and node.get('kind') != 'constructor':
    				#print(f"condition-isConstructor: True\n")
    				functionName = node.get("name")
    				original_arguments = node.get("parameters", {}).get("parameters", [])
    				if functionName and len(original_arguments) == 0:
    					#print(f"condition-functionName: {functionName}\n")
    					if not contains_recursive_call(node.get("body", {}), functionName):
    						suitable_functions.append(node)
    		elif nodeType == "FunctionCall":
    			expression = node.get("expression", {})
    			called_function_name = expression.get("memberName") or expression.get("name")
    			if called_function_name == functionName:
    				return True
    		else:
    			for value in node.values():
    				if isinstance(value, (dict, list)):
    					if traverse(value, functionName):
    						return True
    	elif isinstance(node, list):
    		for item in node:
    			if isinstance(item, (dict, list)):
    				if traverse(item, functionName):
    					return True

    def contains_recursive_call(node, functionName):
        return traverse(node, functionName)

    traverse(ast)
    #print(f"Suitable functions for modification: {[func.get('name') for func in suitable_functions]}")
    return suitable_functions


def action(ast, target_function):
    """
    Modifies the given function by adding a recursive call to it.
    """
    operation_type = None
    function_name = target_function.get("name")
    recursive_call = {
        "documentation": {
            "id": 1462,
            "nodeType": "StructuredDocumentation",
            "src": "16553:231:0",
            "text": " @notice vuln,5-13-1,add,recursive_call,function"
          },
        "nodeType": "ExpressionStatement",
        "expression": {
            "nodeType": "FunctionCall",
            "expression": {
                "nodeType": "Identifier",
                "name": function_name
            },
            "arguments": []
        }
    }
    
    # Assuming 'body' is a 'Block' node containing 'statements'
    #print(f"action-target_function: {target_function}\n")
    if "body" in target_function and target_function["body"] is not None and "statements" in target_function["body"]:
        target_function["body"]["statements"].insert(0, recursive_call)  # Insert after the first statement
    
    return [target_function], operation_type


if __name__ == "__main__":
    mainfunc('5-13-1', condition, action, '5-13-1')