#!/usr/bin/env python3

from common import mainfunc

'''
Vulnerability: 5-7-3  Unused variables source: https://openscv.dei.uc.pt/

condition: find a function definition (no costructor) with a not empty body

action: add a useless node
'''

def condition(ast):
   
    functions_to_modify = []
    
    for node in traverse_nodes(ast, "FunctionDefinition"):
        if node["nodeType"] == "FunctionDefinition" and node.get("body") is not None and node.get("isConstructor") is False:
            functions_to_modify.append(node)
    return functions_to_modify

def traverse_nodes(ast, node_type):
    
    nodes = []

    def traverse(node):
        if isinstance(node, dict):
            if node.get("nodeType") == node_type:
                nodes.append(node)
            for value in node.values():
                if isinstance(value, (dict, list)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)

    traverse(ast)

    return nodes

def action(ast, vulnerable_node):
   
    operation_type = None
    modified_node = vulnerable_node.copy()
    
    modify_function_for_unused_code(modified_node)

    return [modified_node], operation_type

def modify_function_for_unused_code(node):
    #create a useless node
    _unusedVar = {
		    "constant" : False,
			"id" : 6,
			"name" : "unusedVar",
			"nodeType" : "VariableDeclaration",
			"scope" : 17,
    		"src" : "127:22:0",
	    	"stateVariable" : True,
		    "storageLocation" : "default",
    		"typeDescriptions" : 
			{
				"typeIdentifier" : "t_uint256",
				"typeString" : "uint256"
			},
			"typeName" : 
			{
				"id" : 4,
				"name" : "uint256",
				"nodeType" : "ElementaryTypeName",
				"src" : "127:7:0",
				"typeDescriptions" : 
				{
					"typeIdentifier" : "t_uint256",
					"typeString" : "uint256"
				}
			},
			"value" : 
			{
				"argumentTypes" : None,
				"hexValue" : "3432",
				"id" : 5,
				"isConstant" : False,
				"isLValue" : False,
				"isPure" : True,
				"kind" : "number",
				"lValueRequested" : False,
				"nodeType" : "Literal",
				"src" : "147:2:0",
				"subdenomination" : None,
				"typeDescriptions" : 
				{
					"typeIdentifier" : "t_rational_42_by_1",
					"typeString" : "int_const 42"
				},
				"value" : "42"
			}
		}
        
        # Inserisce la variabile nel corpo della funzione
    
    if "body" in node and node["body"] and "statements" in node["body"]:
        node["body"]["statements"].insert(0, _unusedVar)

if __name__ == "__main__":
    mainfunc('5-7-3', condition, action, '5-7-3')