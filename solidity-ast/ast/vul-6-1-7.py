#!/usr/bin/env python3

from common import mainfunc
import copy

'''
Vulnerability: 6.1.7 Missing Constructor source: https://openscv.dei.uc.pt/

condition function task: identify any function call of specific contract inside another contract which is assigned to a variable.

action function task: turn one statement into two independent statements.first statement is the variable part which is supposed to ba boolean and we assign "true" value to cover any kind of usage of that variable and possible business logic.
second statement would be the function call without caring about its return value. actually we assume that the function call return a boolean value. in this way we create a vulnerable contract due to not checking the return value of that specific function call.
'''

def condition(ast):

    vulnerable_variables = []

    # Helper function to check if a public function exists that toggles the state variable
    def has_public_toggle_function(variable_name):
        def check_function(node):
            print(f"condition - 0\n")
            #print(f"condition - node: {node}\n")
            if node.get('nodeType') == 'FunctionDefinition' and node.get('visibility') in ['public', 'external']:
                print(f"condition - 1\n")
                print(f"condition - node: {node}\n")
                if 'kind' in node and node.get('kind') in ['constructor', 'fallback']:
                	print(f"condition - 2\n")
                	return False
                if 'body' in node:
                    print(f"condition - 3\n")
                    for statement in node['body'].get('statements', []):
                        if statement.get('nodeType') == 'ExpressionStatement':
                            print(f"condition - 4\n")
                            expression = statement.get('expression', {})
                            if expression.get('nodeType') == 'Assignment' and expression.get('leftHandSide', {}).get('name') == variable_name:
                                print(f"condition - 5\n")
                                return True
            return False

        for node in ast.get('nodes', []):
            if check_function(node):
                return True
        return False

    # Traverses the AST to find state variables
    def traverse(node):
        if isinstance(node, dict):
            if node.get('nodeType') == 'VariableDeclaration' and node.get('stateVariable') is True and node.get('visibility') not in ['public', 'external'] and node['typeName']['nodeType'] != 'Mapping' and 'bool' in node.get('typeName', {}).get('typeDescriptions', {}).get('typeString', ''):
                variable_name = node.get('name')
                print(f"condition - variable_name: {variable_name}\n")
                if not has_public_toggle_function(variable_name):
                    vulnerable_variables.append(node)
            for value in node.values():
                if isinstance(value, (dict, list)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)

    traverse(ast)
    print(f"condition - vulnerable_nodes: {vulnerable_variables}\n")
    return vulnerable_variables


def action(ast, vulnerable_node):
    new_nodes = []
    operation_type = None
    variable_name = vulnerable_node['name']

    # Assuming we're toggling a boolean state variable,
    # and we decide to set it to true if we don't have its initial value.
    # In real use cases, you might need a more sophisticated approach
    # to determine the appropriate toggle action based on the variable's type and initial value.
    toggle_value = "true"  # Default toggle to true for demonstration purposes
    operation_type = "add"
	# Create a public function node to toggle the state variable's value
    toggle_function = {
    	"documentation": {
            "id": 1462,
            "nodeType": "StructuredDocumentation",
            "src": "16553:231:0",
            "text": " @notice vuln,6-1-7,add,function"
          },
    	"nodeType": "FunctionDefinition",
    	"visibility": "public",
    	"name": f"toggle{variable_name.capitalize()}Value",
    	"parameters": {
        	"id": None,  # You may need to manage IDs yourself if necessary
        	"nodeType": "ParameterList",
        	"parameters": [],
        	"src": ""  # src can be left empty or managed if you're tracking source locations
    	},
    	"returnParameters": {
        	"id": None,  # Manage IDs as needed
        	"nodeType": "ParameterList",
        	"parameters": [],
        	"src": ""
    	},
    	"body": {
        	"id": None,  # Manage IDs as needed
        	"nodeType": "Block",
        	"src": "",  # src can be empty or managed
        	"statements": [
            	{
                	"nodeType": "ExpressionStatement",
                	"expression": {
                    	"nodeType": "Assignment",
                    	"operator": "=",
                    	"leftHandSide": {
                        	"nodeType": "Identifier",
                        	"name": variable_name,
                    	},
                    	"rightHandSide": {
                        	"nodeType": "Literal",
                        	"kind": "bool",
                        	"value": "true", #str(initial_value).lower(),
                        	"typeDescriptions": {
                            	"typeIdentifier": "t_bool",
                            	"typeString": "bool"
                        	}
                    	},
                    	"src": ""  # src can be empty or managed
                	},
                	"src": ""  # src can be empty or managed
            	}
        	]
    	},
    	"implemented": True,  # This should be true to indicate the function is defined, not just declared
    	"stateMutability": "nonpayable",  # Adjust based on your function's needs
    	"visibility": "public"  # This is already set at the top, just reiterating for clarity
	}
    
    new_nodes.append(toggle_function)
    return new_nodes, operation_type


if __name__ == "__main__":
    mainfunc('6-1-7', condition, action, '6-1-7')