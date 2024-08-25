#!/usr/bin/env python3

from commonc import mainfunc

'''
Vulnerability: 1.3.1 Improper Check of External Call Return Value 
source: https://openscv.dei.uc.pt/

condition function task: identify any function call of specific contract inside another contract which is assigned to a variable.
bool result = product.addProduct();

action function task: turn one statement into two independent statements. first statement is the variable part which is supposed to ba boolean and we assign "true" value to cover any kind of usage of that variable and possible business logic.
second statement would be the function call without caring about its return value. actually we assume that the function call return a boolean value. in this way we create a vulnerable contract due to not checking the return value of that specific function call.
bool result = true;
product.addProduct();

assumptions:
	- the function which is called, assumed to return a boolean value
	- type of the variable is assumed to be a boolean
'''

def condition(ast):
    vulnerable_nodes = []

    # Iterate over all nodes in the AST
    def search_nodes(node):
        # Check if node is a VariableDeclarationStatement and has an initialValue of type FunctionCall
        if node.get("nodeType") == "VariableDeclarationStatement" and "initialValue" in node:
            initial_value = node["initialValue"]
            if initial_value and initial_value.get("nodeType") == "FunctionCall":
                # Check if the function call is from a contract instance
                if initial_value["expression"].get("nodeType") == "MemberAccess":
                	#print(f"condition-initial_value: {initial_value['expression']}\n")
                	if initial_value["expression"].get("expression").get("typeDescriptions").get("typeString") not in ['uint256', 'bytes32', 'bytes memory']:
                		vulnerable_nodes.append(node)

    # Recursive search through the AST
    def traverse_nodes(node):
        if isinstance(node, dict):
            search_nodes(node)
            for key in node:
                traverse_nodes(node[key])
        elif isinstance(node, list):
            for elem in node:
                traverse_nodes(elem)

    traverse_nodes(ast)
    #print(f"condition-vulnerable_nodes: {vulnerable_nodes}\n")
    return vulnerable_nodes

def action(ast, target_node):
    # Ensure the target node is the correct type
    if target_node.get("nodeType") != "VariableDeclarationStatement":
        raise ValueError("Target node is not a VariableDeclarationStatement")

    # Get the FunctionCall from the initialValue of the VariableDeclarationStatement
    function_call = target_node.get("initialValue", {})

    # Prepare Literal nodes for replacements based on type
    literals = {
        "bool": {
            "nodeType": "Literal",
            "value": "true",
            "kind": "bool",
            "hexValue": "74727565",
            "typeDescriptions": {"typeIdentifier": "t_bool", "typeString": "bool"}
        },
        "uint": {
            "nodeType": "Literal",
            "value": "10",
            "hexValue": "3130",
            "typeDescriptions": {"typeIdentifier": "t_uint256", "typeString": "uint256"}
        },
        "bytes32": {
            "nodeType": "Literal",
            "value": "10",
            "hexValue": "3130",
            "typeDescriptions": {"typeIdentifier": "t_bytes32", "typeString": "bytes32"}
        },
        "address": {
    		"nodeType": "Literal",
    		"value": "0x874D72e8F9908fDC55a420Bead9A22a8A5b20D91",  # Example Ethereum address
    		"hexValue": "307838373444373265384639393038664443353561343230426561643941323261384135623230443931",  # Hexadecimal ASCII values for the address string
    		"typeDescriptions": {
        		"typeIdentifier": "t_address",
        		"typeString": "address"
    		}
		}
    }

    # Handle destructuring assignments
    new_statements = []
    if isinstance(target_node['declarations'], list):
        for declaration in target_node['declarations']:
            print(f"action-declaration: {declaration}\n")
            if declaration is not None:
            	type_name = declaration['typeName']['name']
            	print(f"action-type_name: {type_name}\n")
            	print(f"action-declaration['name']: {declaration['name']}\n")
            	new_var_decl = declaration.copy()
            	new_var_decl['initialValue'] = literals.get(type_name.lower(), literals['bool'])  # Default to bool
            	print(f"action-new_var_decl['initialValue']: {new_var_decl['initialValue']}\n")
            	"""new_statements.append({
                	"nodeType": "ExpressionStatement",
                	"expression": {
                    	"nodeType": "Assignment",
                    	"operator": "=",
                    	"leftHandSide": {
                        	"nodeType": "Identifier",
                        	"name": declaration['name'],
                        	"kind": "bool",
                        	"typeName": {"id": 1565, "name": "bool", "nodeType": "ElementaryTypeName", "src": "29983:4:0", "typeDescriptions": {"typeIdentifier": "t_bool", "typeString": "bool"}}
                    	},
                    	"rightHandSide": literals.get(type_name.lower(), literals['bool']) #new_var_decl['initialValue']
                	}
            	})"""
            	new_statements.append({
                	"nodeType": "VariableDeclarationStatement",
                	"declarations": [new_var_decl],
                	"initialValue": new_var_decl['initialValue']
            	})

    print(f"action-new_statements: {new_statements}\n")
    # Append the original function call as a standalone statement
    new_statements.append({
        "documentation": {
            "id": 1462,
            "nodeType": "StructuredDocumentation",
            "src": "16553:231:0",
            "text": " @notice vuln,1-3-1,replace,function_call,function"
        },
        "nodeType": "ExpressionStatement",
        "expression": function_call,
    })

    return new_statements, None
    
def actionold3(ast, target_node):
    # Ensure the target node is the correct type
    operation_type = None
    if target_node.get("nodeType") != "VariableDeclarationStatement":
        raise ValueError("Target node is not a VariableDeclarationStatement")

    # Get the FunctionCall from the initialValue of the VariableDeclarationStatement
    function_call = target_node.get("initialValue", {})

    # Create a new Literal node for 'true'
    bool_literal = {
        "nodeType": "Literal",
        "value": "true",
        "hexValue": "74727565",  # Hexadecimal representation of 'true'
        "typeDescriptions": {
            "typeIdentifier": "t_bool",
            "typeString": "bool"
        }
    }
    
    # Create a new Literal node for integer
    int_literal = {
        "nodeType": "Literal",
        "value": "10",
        "hexValue": "3130",
        "kind": "number",
        "typeDescriptions": {
            "typeIdentifier": "t_uint256",
            "typeString": "uint256"
        }
    }
    
    # Create a new Literal node for integer
    byte_literal = {
        "nodeType": "Literal",
        "value": "10",
        "hexValue": "3130",
        "typeDescriptions": {
            "typeIdentifier": "t_bytes32",
            "typeString": "bytes32"
        }
    }

    # Update the original VariableDeclarationStatement to assign 'true'
    new_var_decl = target_node.copy()
    print(f"action-new_var_decl: {new_var_decl}\n")
    new_var_decl_elements = new_var_decl['declarations']
    for new_var_decl_element in new_var_decl_elements:
    	if new_var_decl_element is not None:
    		#print(f"\n\naction-new_var_decl_element: {new_var_decl_element}\n")
    		print(f"\n\naction-new_var_decl_element: {new_var_decl_element}\n")
    		if 'typeName' in new_var_decl_element and new_var_decl_element['typeName']['name'] == 'uint':
    			new_var_decl["initialValue"] = int_literal
    		elif 'typeName' in new_var_decl_element and new_var_decl_element['typeName']['name'] == 'bytes32':
    			new_var_decl["initialValue"] = byte_literal
    		else:
    			new_var_decl["initialValue"] = bool_literal
    	else:
    		print(f"\n\naction-new_var_decl_element-None: {new_var_decl_element}\n")

    print(f"action-new_var_decl: {new_var_decl}\n")
    # Create a new ExpressionStatement node for the FunctionCall
    function_call_node = {
        "documentation": {
            "id": 1462,
            "nodeType": "StructuredDocumentation",
            "src": "16553:231:0",
            "text": " @notice vuln,1-3-1,replace,function_call,function"
          },
        "nodeType": "ExpressionStatement",
        "expression": function_call,
        "id": function_call.get("id"),  # Reuse the ID from the function call
        "src": function_call.get("src")
    }

    return [new_var_decl, function_call_node], operation_type

if __name__ == "__main__":
    mainfunc('Removes return statements.', condition, action, '1-3-1')