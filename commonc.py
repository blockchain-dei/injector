from serializerc import readastcompact, writeastcompact, iscompilable, getContractSourceCode, convert_ast_source, writesourcecode
import os
import argparse
import copy
import re


def find_statement_index(parent, statement_node_id):
    # Initialize index to None
    nodeindex = None

    # Check if parent is the target node
    if parent.get('id') == statement_node_id:
        return 0  # Found at the top level

    # Check in 'initialValue' if it's a VariableDeclarationStatement
    if parent.get('nodeType') == 'VariableDeclarationStatement' and 'initialValue' in parent:
        if parent['initialValue'].get('id') == statement_node_id:
            return 0  # Found in initialValue directly
        else:
            # If initialValue has further nested structures, search within them
            result = find_node_by_id(parent['initialValue'], statement_node_id)
            if result:
                return 0  # Found within initialValue

    # If not found yet, check in 'nodes'
    if 'nodes' in parent:
        for i, child in enumerate(parent['nodes']):
            if child['id'] == statement_node_id:
                nodeindex = i
                break  # Exit loop once the matching node is found

    # If not found in 'nodes', check in 'body'->'statements' if available
    if nodeindex is None and 'body' in parent and 'statements' in parent['body']:
        for i, child in enumerate(parent['body']['statements']):
            if child['id'] == statement_node_id:
                nodeindex = i
                break  # Exit loop once the matching node is found

    return nodeindex

def find_node_by_id(ast, id):
    #if ast is None:
        #return None

    # Check if the current node is the one we're looking for
    if ast.get('id') == id:
        return ast

    # Define a recursive search function
    def recursive_search(node):
    	if isinstance(node, dict):
    		# Process node dictionary
    		if 'id' in node and node['id'] == id:
    			return node
    		for value in node.values():
    			found = recursive_search(value)
    			if found:
    				return found
    	elif isinstance(node, list):
    		# Process list of nodes
    		for item in node:
    			found = recursive_search(item)
    			if found:
    				return found
    	return None

    # Check various properties that can contain nested nodes
    properties_to_check = [
        'nodes', 'body', 'statements', 'initialValue',
        'leftHandSide', 'rightHandSide', 'expression', 'declarations',
        'parameters', 'returnParameters', 'trueBody', 'falseBody'
    ]

    for prop in properties_to_check:
        if prop in ast:
            result = recursive_search(ast[prop])
            if result:
                return result

    return None
    
def find_node_id_by_type_and_name(ast, node_type, node_name):
    """
    Recursively search the AST for a node of a given type and name, returning its ID.

    :param ast: The AST or a sub-tree of the AST.
    :param node_type: The type of the node to find.
    :param node_name: The name of the node to find.
    :return: The ID of the found node, or None if not found.
    """
    # Check if the current node matches the criteria
    if ast.get('nodeType') == node_type and ast.get('name') == node_name:
        return ast.get('id')

    # Recursively search in child nodes
    for key, value in ast.items():
        if isinstance(value, dict):  # Single child node
            found_id = find_node_id_by_type_and_name(value, node_type, node_name)
            if found_id is not None:
                return found_id
        elif isinstance(value, list):  # List of child nodes
            for item in value:
                if isinstance(item, dict):
                    found_id = find_node_id_by_type_and_name(item, node_type, node_name)
                    if found_id is not None:
                        return found_id

    # If the node is not found in the current branch
    return None
    
def transform_vardecstate_expstate(ast_node):
    if ast_node['nodeType'] != 'VariableDeclarationStatement':
        raise ValueError('Node must be a VariableDeclarationStatement')

    # Extracting the function call from the variable declaration
    function_call = ast_node['initialValue']

    # Creating a new ExpressionStatement node
    expression_statement = {
        "expression": function_call,
        "id": ast_node['id'],  # You may want to assign a new unique ID here
        "nodeType": "ExpressionStatement",
        "src": ast_node['src']
    }

    return expression_statement
    
def find_contract_definitions(ast):
	contract_names = []
	contract_defs = []
	for node in ast['nodes']:
		if node['nodeType'] == 'ContractDefinition':
			contract_names.append(node['name'])
			contract_defs.append(node)
	return (contract_names, contract_defs)
    #return [(node['name'], node) for node in ast['nodes'] if node['nodeType'] == 'ContractDefinition']

def is_contract_type(type_string, contract_defs):
    return any(contract['name'] in type_string for contract in contract_defs)

def get_contract_name_from_type(type_string, contract_defs):
    for contract in contract_defs:
        if contract['name'] in type_string:
            return contract['name']
    return None


def identify_all_variables_with_additional_attributes(ast):
    #interactions = []
    functions = []
    variables = []
    
    def process_variable(node, contract_name, function_name=None, var_type=None):
        if node["nodeType"] == "VariableDeclaration":
            visibility = node.get("visibility", "default")
            is_constant = node.get("constant", False)
            has_value = "value" in node and node["value"] is not None
            #print(f"process_variable - node: {node}\n")
            node_type = node["typeName"]["nodeType"]
            #print(f"process_variable - node_type: {node_type}\n")
            if node_type == "Mapping":
                key_type = node["typeName"]["keyType"]["typeDescriptions"]["typeString"]
                value_type = node["typeName"]["valueType"]["typeDescriptions"]["typeString"]
                object_type = f"mapping({key_type} => {value_type})"
            else:
                #object_type = node["typeName"]["typeString"]
                object_type = node["typeName"]["name"]
            if has_value:
                variableValue = get_variable_value(node["value"])
            else:
                variableValue = ""
            variables.append({
                "nodeId": node["id"],
                "type": var_type if var_type else "state variable",
                "contract": contract_name,
                "function": function_name,
                "object_type": object_type,
                "object_name": node.get("name", ""),
                "visibility": visibility,
                "is_constant": is_constant,
                "has_value": has_value,
                "variableValue": variableValue
            })
    
    def process_func_variable(parentNode, node, contract_name, function_name=None, var_type=None):
        if node["nodeType"] == "VariableDeclaration":
            visibility = node.get("visibility", "default")
            is_constant = node.get("constant", False)
            has_value = "initialValue" in parentNode and parentNode["initialValue"] is not None
            #print(f"process_variable - node: {node}\n")
            node_type = node["typeName"]["nodeType"]
            #print(f"process_variable - node_type: {node_type}\n")
            if node_type == "Mapping":
                key_type = node["typeName"]["keyType"]["typeDescriptions"]["typeString"]
                value_type = node["typeName"]["valueType"]["typeDescriptions"]["typeString"]
                object_type = f"mapping({key_type} => {value_type})"
            else:
                #object_type = node["typeName"]["typeString"]
                object_type = node["typeName"]["name"]
            if has_value:
            	initialValueNode = parentNode["initialValue"]
            	if initialValueNode["nodeType"] == "Identifier":
            		variableValue = initialValueNode["name"]
            	elif initialValueNode["nodeType"] == "Literal":
            		variableValue = initialValueNode["value"]
            	elif initialValueNode["nodeType"] == "FunctionCall":
            		# Handle function call; for simplicity, let's just use a placeholder string
            		functionCallExpression = initialValueNode["expression"]
            		if functionCallExpression["nodeType"] == "MemberAccess":
            			objectName = functionCallExpression["expression"]["name"]
            			functionName = functionCallExpression["memberName"]
            			variableValue = f"{objectName}.{functionName}()"
            		else:
            			# Handle other cases or unknown function call types
            			variableValue = "<unknown function call>"
            	else:
            		variableValue = "unknown initial value"
            else:
            	variableValue = ""
            variables.append({
                "nodeId": node["id"],
                "type": var_type if var_type else "state variable",
                "contract": contract_name,
                "function": function_name,
                "object_type": object_type,
                "object_name": node.get("name", ""),
                "visibility": visibility,
                "is_constant": is_constant,
                "has_value": has_value,
                "variableValue": variableValue
            })
            
    def get_variable_value(node):
    	# This function should be extended based on how complex the values in your AST can be.
    	# For now, it handles simple literals and returns raw value for complex types.
    	#if node.get("nodeType") == "Literal":
    		#return node.get("value")
    	if node is None or 'value' not in node:
    		return None
    	
    	value_node = node['value']
    	#print(f"get_variable_value - value_node: {value_node}\n")
    	#return value_node.get('value')
    	return value_node
    	#else:
    		# Return a string representation of complex types (like mapping, arrays, etc.)
    		#return str(node)
    
    def process_function(node, contract_name):
        #if not node.get('isConstructor', False):
        visibility = node["visibility"]
        stateMutability = node["stateMutability"]
        #has_input = "parameters" in node["parameters"] and node["parameters"]["parameters"] is not None
        #has_return = "parameters" in node["returnParameters"] and node["returnParameters"]["parameters"] is not None
        has_input = "parameters" in node and "parameters" in node["parameters"] and len(node["parameters"]["parameters"]) > 0
        has_return = "returnParameters" in node and "parameters" in node["returnParameters"] and len(node["returnParameters"]["parameters"]) > 0
        if has_return:
        	return_type = node["returnParameters"]["parameters"][0]["typeDescriptions"]["typeString"]
        else:
        	return_type = ""
        result = {
        "has_call": False,
        "call_object": "",
        "call_object_assigned": "0",
        "call_funccall_nodeId": "",
        "call_funccall_pnodeId": "0",
        "call_function": "",
        "call_function_input": []
        }
        for param in node["parameters"]["parameters"]:
            process_variable(param, contract_name, function_name=node["name"], var_type="function input parameter")
        for param in node["returnParameters"]["parameters"]:
            process_variable(param, contract_name, function_name=node["name"], var_type="function output parameter")
        for statement in node.get('body', {}).get('statements', []):
        	if statement['nodeType'] == 'VariableDeclarationStatement':
        		for decl in statement.get('declarations', []):
        			process_func_variable(statement, decl, contract_name, function_name=node["name"], var_type="function variable")
        		if "initialValue" in statement and statement["initialValue"] is not None:
        			initialNode = statement["initialValue"]
        			if "expression" in initialNode and initialNode["nodeType"] == "FunctionCall":
        				result = check_function_call(initialNode)
        				result["call_funccall_pnodeId"] = statement['id']
        				result["call_object_assigned"] = statement["declarations"][0]["name"]
        		elif "expression" in statement and statement["expression"]["nodeType"] == "FunctionCall":
        			result = check_function_call(statement["expression"])
        functions.append({
                "nodeId": node["id"],
                "type": "normal function",
                "contract": contract_name,
                "function": node["name"],
                "stateMutability": stateMutability,
                #"object_name": node.get("name", ""),
                "visibility": visibility,
                "has_input": has_input,
                "has_return": has_return,
                "return_type": return_type,
                "has_call": result["has_call"],
                "call_object_assigned": result["call_object_assigned"],
                "call_object": result["call_object"],
                "call_funccall_nodeId": result["call_funccall_nodeId"],
                "call_funccall_pnodeId": result["call_funccall_pnodeId"],
                "call_function": result["call_function"],
                "call_function_input": result["call_function_input"]
            })

    def check_function_call(expression):
    	#print(f"check_function_call-expression: {expression}")
    	result = {
    		"has_call": False,
    		"call_object": "",
    		"call_object_assigned": "0",
    		"call_funccall_nodeId": "",
    		"call_funccall_pnodeId": "0",
    		"call_function": "",
    		"call_function_input": "",
    		"call_function_output": []
    	}
    	if expression["nodeType"] == "FunctionCall":
    		#print(f"check_function_call- has_call: True\n")
    		result["has_call"] = True
    		result["call_funccall_nodeId"] = expression["id"]
    		if expression["expression"]["nodeType"] == "MemberAccess":
    			#print(f"check_function_call- MemberAccess\n")
    			member_access = expression["expression"]
    			# Check if the expression is a further MemberAccess or a direct Identifier
    			if member_access["expression"]["nodeType"] == "MemberAccess":
    				# Nested MemberAccess, e.g., msg.sender.transfer
    				#print(f"check_function_call- nested_member_access\n")
    				nested_member_access = member_access["expression"]
    				result["call_object"] = nested_member_access["expression"]["name"]
    				if nested_member_access["expression"]["nodeType"] == "Identifier":
    					result["call_function"] = nested_member_access["memberName"]
    				else:
    					#print(f"check_function_call- normal_member_access\n")
    					result["call_function"] = nested_member_access["memberName"] + '.' + member_access["memberName"]
    				#print(f"check_function_call- call_object: {result['call_object']}\n")
    				#print(f"check_function_call- call_function: {result['call_function']}\n")
    			elif member_access["expression"]["nodeType"] == "Identifier":
    				# Direct MemberAccess, e.g., product.addProduct
    				#print(f"check_function_call- Identifier\n")
    				result["call_object"] = member_access["expression"]["name"]
    				#result["call_object_nodeId"] = member_access["expression"]["id"]
    				result["call_function"] = member_access["memberName"]
    				#print(f"check_function_call- call_object: {result['call_object']}\n")
    				#print(f"check_function_call- call_function: {result['call_function']}\n")
    			else:
    				# Handle other cases or raise an error
    				#print(f"check_function_call- error\n")
    				raise ValueError("Unexpected AST structure for function call")
    			# Extract input arguments if present
    			if expression["arguments"]:
    				result["call_function_input"] = [arg.get("name", str(arg)) for arg in expression["arguments"]]
    				#print(f"check_function_call- call_function_input: {result['call_function_input']}\n")
    				# Output cannot be directly extracted from AST in this context
    		elif expression["expression"]["nodeType"] == "Identifier":
    			result["call_object"] = expression["expression"]["name"]
    			#result["call_object_nodeId"] = expression["expression"]["id"]
    			result["call_function"] = ""
    			#print(f"check_function_call- call_object: {result['call_object']}\n")
    			#print(f"check_function_call- call_function: {result['call_function']}\n")
    		else:
    			result["call_object"] = "unknown"
    			#result["call_object_nodeId"] = "unknown"
    			result["call_function"] = "unknown"
    			#print(f"check_function_call- call_object: {result['call_object']}\n")
    			#print(f"check_function_call- call_function: {result['call_function']}\n")
    		
    		result["call_function_input"] = []
    		if expression["arguments"]:
    			for arg in expression["arguments"]:
    				result["call_function_input"].append(parse_expression(arg))
    			
    	#print(f"check_function_call- has_call: {has_call}")
    	return result
    
    def parse_expression(exp):
    	if exp["nodeType"] == "Identifier":
    		return exp["name"]
    	elif exp["nodeType"] == "Literal":
    		return exp["value"]
    	elif exp["nodeType"] == "BinaryOperation":
    		left = parse_expression(exp["leftExpression"])
    		right = parse_expression(exp["rightExpression"])
    		operator = exp["operator"]
    		return f"({left} {operator} {right})"
    	else:
    		return "unknown"
    	return str(exp)
    
    def process_contract(node):
        for child_node in node["nodes"]:
            if child_node["nodeType"] == "VariableDeclaration":
                process_variable(child_node, node["name"])
            elif child_node["nodeType"] == "FunctionDefinition":
                process_function(child_node, node["name"])

    for node in ast["nodes"]:
        if node["nodeType"] == "ContractDefinition":
            process_contract(node)

    #print(f"identify_all - all functions: {functions}\n")
    return (functions, variables)

def filter_contract_interactions(variables, contract_defs):
    return [var for var in variables if is_contract_type(var['object_type'], contract_defs)]

def getVariableInfo(variable_name, ast, contract_name=None, function_name=None, path=None, parent_node=None):
    usages = []

    if path is None:
        path = []

    if isinstance(ast, dict):
        # Update contract and function names based on the current node
        if ast.get("nodeType") == "ContractDefinition":
            contract_name = ast.get("name")
            function_name = None
            path = [contract_name]

        if ast.get("nodeType") == "FunctionDefinition":
            function_name = ast.get("name")
            path = [contract_name, function_name]

        # Check if the current node is a variable definition of interest
        if ast.get("nodeType") == "VariableDeclaration" and ast.get("name") == variable_name:
            usages.append((contract_name, function_name or "root", "definition", ast.get("id")))

        # Recursively process each key-value pair in the dictionary
        for key, value in ast.items():
            new_path = path + [key] if isinstance(value, (dict, list)) else path
            new_usages = getVariableInfo(variable_name, value, contract_name, function_name, new_path, ast)
            usages.extend(new_usages)

            # Check if the current node is the variable of interest after processing children
            if key == "name" and value == variable_name and "nodeType" in ast and ast["nodeType"] == "Identifier":
                #usage_type = determineUsageType(new_path, ast, parent_node, variable_name)
                usage_type = determineUsageType(new_path, parent_node)
                usages.append((contract_name, function_name or "root", usage_type, ast.get("id")))

    elif isinstance(ast, list):
        # Recursively process each item in the list
        for item in ast:
            usages.extend(getVariableInfo(variable_name, item, contract_name, function_name, path, parent_node))

    return usages

def determineUsageType(path, parent_node):
    if parent_node.get("nodeType") == "Return":
        return "return"

    if "condition" in path and parent_node.get("nodeType") == "BinaryOperation":
        return "ifCondition"

    if "arguments" in path and parent_node.get("nodeType") == "BinaryOperation":
        return "functionCallInput"

    if "leftHandSide" in path:
        return "getValue"

    if "rightHandSide" in path or "initialValue" in path:
        return "assigned"

    return "usage"
    
def varCheckOnlyDef(variableUsage):
	# Check if the array has only one item
    if len(variableUsage) == 1:
        # Extract the item
        item = variableUsage[0]
        
        # Check if the third attribute of the item is "definition"
        if len(item) > 2 and item[2] == "definition":
            return True
        else:
            return False
    else:
        return False

def find_parent_id(ast, child_id):
    def search_node(nodes, search_id):
        for node in nodes:
            # Check if this node matches the search_id
            if node.get('id') == search_id:
                return True, node

            # If the node has 'nodes' key, search recursively inside
            if 'nodes' in node:
                found, parent_node = search_node(node['nodes'], search_id)
                if found:
                    return True, node  # Return the current node as the parent

            # If the node has a 'body' that contains 'statements', search inside the statements
            if 'body' in node and node['body'] is not None and 'statements' in node['body']:
                found, parent_node = search_node(node['body']['statements'], search_id)
                if found:
                    return True, node  # Return the current node as the parent

        return False, None

    # Adjusted to start the search with the 'nodes' array in the 'SourceUnit'
    _, parent_node = search_node(ast['nodes'], child_id)
    if parent_node is not None:
        return parent_node.get('id')  # Return the parent ID
    else:
        return None  # No parent found, or the node does not exist

# Assuming 'ast_sample' is your AST structure and you're looking for the parent of node with ID 209
# parent_id = find_parent_id(ast_sample, 209)
# print("Parent ID:", parent_id)

def traverse_and_update(parent, key, node, node_id, new_nodes):
    # Handling dictionary nodes
    if isinstance(node, dict):
        if node.get('id') == node_id:
            # Handle both single node replacement and multiple node replacement (including removal)
            if isinstance(parent, dict):
                parent[key] = new_nodes if isinstance(new_nodes, list) else [new_nodes]
            elif isinstance(parent, list):
                index = parent.index(node)
                if isinstance(new_nodes, list):
                    parent[index:index+1] = new_nodes  # Replace with list of new nodes or remove
                else:
                    parent[index] = new_nodes  # Replace the single node
            return True
        else:
            for k, v in node.items():
                if isinstance(v, (dict, list)):
                    if traverse_and_update(node, k, v, node_id, new_nodes):
                        return True

    # Handling list nodes
    elif isinstance(node, list):
        for i, item in enumerate(node):
            if traverse_and_update(node, i, item, node_id, new_nodes):
                return True

    return False

def traverse_and_add(ast, node_id, new_nodes):
    # Define the recursive function to traverse the AST and find the contract
    def traverse_and_find_contract(node, contract_node_id):
        if isinstance(node, dict):
            if node.get('type') == 'ContractDefinition' and node.get('id') == contract_node_id:
                return node
            else:
                for value in node.values():
                    if isinstance(value, (dict, list)):
                        result = traverse_and_find_contract(value, contract_node_id)
                        if result is not None:
                            return result
        elif isinstance(node, list):
            for item in node:
                result = traverse_and_find_contract(item, contract_node_id)
                if result is not None:
                    return result
        return None

    # Find the contract node
    contract_node_id = find_parent_id(ast, node_id)
    #print(f"traverse_and_add-node_id: {ast['id']}\n")
    #print(f"traverse_and_add-parent_id: {contract_node_id}\n")
    #contract_node = traverse_and_find_contract(ast, contract_node_id)
    last_node_id = ast['id']
    contract_node = find_node_by_id(ast, contract_node_id)
    if contract_node is None:
        raise ValueError(f"No contract node found with id {node_id}")
    last_node_src = find_last_node_src(contract_node)
	# Set the 'src' for new nodes, if we were able to determine a position
    if last_node_src:
        for new_node in new_nodes if isinstance(new_nodes, list) else [new_nodes]:
            #print(f"traverse_and_add-new_node1: {new_node}\n")
            new_node['src'] = last_node_src
            last_node_id += 1
            new_node['id'] = last_node_id
            #print(f"traverse_and_add-last_node_src: {last_node_src}\n")
            #print(f"traverse_and_add-new_node2: {new_node}\n")
            
    # Add the new_nodes to the contract's 'subNodes'
    if 'nodes' not in contract_node:
        contract_node['nodes'] = []
    contract_node['nodes'].extend(new_nodes if isinstance(new_nodes, list) else [new_nodes])

def update_node_in_ast(ast, node_id, new_nodes, operation_type=None):
    if operation_type == 'add':
        traverse_and_add(ast, node_id, new_nodes)
    else:
        if not traverse_and_update(None, None, ast, node_id, new_nodes):
            raise ValueError(f"No node found with id {node_id}")
        
def calculate_nested_lengths(node):
    total_length = 0
    if isinstance(node, dict):
        # Exclude 'body' nodes from the length calculation
        if node.get('nodeType') != 'Block':
            src = node.get('src', '')
            if src:
                parts = src.split(':')
                if len(parts) >= 2:
                    # Add the length of the current node if 'src' is present and properly formatted
                    total_length += int(parts[1])
                    #print(f"calculate_nested_lengths1-total_length: {total_length}\n")

        # Recursively calculate the length of nested nodes
        for key, value in node.items():
            if key != 'body' and isinstance(value, (list, dict)):
                total_length += calculate_nested_lengths(value)

    elif isinstance(node, list):
        for item in node:
            total_length += calculate_nested_lengths(item)
            #print(f"calculate_nested_lengths2-total_length: {total_length}\n")

    return total_length

def find_last_node_src(contract_node):
    if 'nodes' in contract_node and contract_node['nodes']:
        last_node = contract_node['nodes'][-1]
        if 'src' in last_node:
            src_parts = last_node['src'].split(':')
            if len(src_parts) == 3:
                start, length, file = map(int, src_parts)
                # Calculate total length of all nested nodes except 'body'
                nested_length = calculate_nested_lengths(last_node)
                # Adjust new_start to account for nested lengths
                new_start = start + 1 + nested_length + 1 # +1 for potential whitespace
                #print(f"find_last_node_src-start: {start}\n")
                #print(f"find_last_node_src-nested_length: {nested_length}\n")
                #print(f"find_last_node_src-new_start: {new_start}\n")
                return f"{new_start}:0:{file}"
    return None
    
def find_last_node_srcold(contract_node):
    if 'nodes' in contract_node and contract_node['nodes']:
        # Assuming the nodes are in order, take the last node
        last_node = contract_node['nodes'][-1]
        print(f"find_last_node_src-last_node: {last_node}\n")
        if 'src' in last_node:
            src_parts = last_node['src'].split(':')
            if len(src_parts) == 3:
                start, length, file = map(int, src_parts)
                # Estimate the new start as last_node's start + length + some whitespace
                new_start = start + length + 27 + 1 # +1 or more to account for newline/whitespace
                return f"{new_start}:0:{file}"  # New node's exact length unknown at this point
    return None
    
def injectold(infile, cond, act, suffix):
    inj = Injector(cond, act)
    print(f"inject-infile: {infile}\n")
    r1 = re.compile(".*.sol")
    vulnerable_list = list(filter(r1.match, os.listdir(infile)))
    vulnerable_list.sort()
    vulnerableFiles = 0
    for contract in vulnerable_list:
    	inj.injectall(contract, infile[2:], suffix)
    	vulnerableFiles +=1
    #print(f"\nnumber of total files that tried to inject faults: {vulnerableFiles} in {infile[2:]} directory\n")
    
def inject(input_path, cond, act, suffix):
    inj = Injector(cond, act)
    #print(f"inject-input_path: {input_path}\n")
    r1 = re.compile(".*\.sol$")
    vulnerableFiles = 0
    if os.path.isdir(input_path):
        contract_list = list(filter(r1.match, os.listdir(input_path)))
        contract_list.sort()
        for contract in contract_list:
            #print(f"inject-contract: {contract}\n")
            inj.injectall(contract, input_path[2:], suffix)
            vulnerableFiles +=1
    else:
        if r1.match(input_path):
            inj.injectall(input_path, "", suffix) # Process single file
            vulnerableFiles +=1
            
class Injector:
    def __init__(self, cond, act):
        self.cnt = 0
        self.cond = cond
        self.act = act
    '''
    def find_node_by_id2(self, ast, id):
    	if ast['id'] == id:
    		return ast
    	if 'nodes' in ast:
    		for child in ast['nodes']:
    			result = self.find_node_by_id(child, id)
    			if result:
    				return result
    	return None
    '''
    def deepest_nodes(self, node, parent=None, nodeindex=None, found_nodes=[]):
    # Recursively find the deepest nodes in the AST, tracking parent and index.
    	if 'nodes' in node and node['nodes']:
    		for idx, child in enumerate(node['nodes']):
    			# Pass the current node as the parent and the index of the child
    			self.deepest_nodes(child, node, idx, found_nodes)
    	else:
    		# Append a tuple of the node, its parent, and the index in the parent
    		found_nodes.append((node, parent, nodeindex))
    	return found_nodes
    
    def load_source_code(self, file_path):
    	with open(file_path, 'r', encoding='utf-8') as file:
        	return file.readlines()
    
    def get_source_lines_for_node(self, ast, source_code_lines, node_id):
    	#print(f"get_source_lines_for_node-hello\n")
    	node = find_node_by_id(ast, node_id)
    	#print(f"get_source_lines_for_node-hello2\n")
    	#print(f"get_source_lines_for_node-node_id: {node_id}\n")
    	#print(f"get_source_lines_for_node-node-id: {node['id']}\n")
    	#print(f"get_source_lines_for_node-node: {node}\n")
    	if node is None:
        	return (-1, -1)

    	src = node.get('src', '')
    	#print(f"get_source_lines_for_node-src: {src}\n")
    	start_byte, length = map(int, src.split(':')[:2])
    	#print(f"get_source_lines_for_node-start_byte: {start_byte}\n")
    	#print(f"get_source_lines_for_node-length: {length}\n")
    	text = ''.join(source_code_lines)

    	#start_byte += 50
    	#print(f"get_source_lines_for_node-text: {text}\n")
    	# Adjust for character offsets
    	#start_byte = 8097
    	#print(f"get_source_lines_for_node-start_byte: {start_byte}\n")
    	nested_length = calculate_nested_lengths(node)
    	new_start=start_byte+1+nested_length+1
    	pre_text = text[:new_start + length]
    	#print(f"get_source_lines_for_node-pre_text: {pre_text}\n")
    	start_line = pre_text.count('\n') + 1
    	#print(f"get_source_lines_for_node-start_line: {start_line}\n")
    	post_text = text[new_start:new_start + length + 50]
    	#print(f"get_source_lines_for_node-post_text: {post_text}\n")
    	end_line = start_line + post_text.count('\n')

    	#print(f"get_source_lines_for_node-end_line: {end_line}\n")
    	#print(f"get_source_lines_for_node-code22: {source_code_lines[start_line-1:end_line]}\n")
    	#return '\n'.join(source_code_lines[start_line-1:end_line]), start_line, end_line
    	return start_line, end_line
    
    def read_sol_file_to_lines(self, file_path):
    	with open(file_path, 'r') as file:
       		source_code_lines = file.readlines()
    	return source_code_lines
    
    def get_source_lines_for_nodeold(self, ast, source_code_lines, node_id):
    	node = find_node_by_id(ast, node_id)
    	print(f"get_source_lines_for_node-node_id: {node_id}\n")
    	print(f"get_source_lines_for_node-node: {node}\n")
    	if node and 'src' in node:
        	src_info = node['src'].split(':')
        	start_byte = int(src_info[0])
        	length = int(src_info[1])
        	print(f"get_source_lines_for_node-src_info: {src_info}\n")
        	print(f"get_source_lines_for_node-start_byte: {start_byte}\n")
        	print(f"get_source_lines_for_node-length: {length}\n")
        	# Convert byte offset to line numbers
        	start_line = sum(line.endswith('\n') for line in source_code_lines[:start_byte]) + 1
        	end_byte = start_byte + length
        	end_line = sum(line.endswith('\n') for line in source_code_lines[:end_byte]) + 1
        	print(f"get_source_lines_for_node-start_line: {start_line}\n")
        	print(f"get_source_lines_for_node-end_byte: {end_byte}\n")
        	print(f"get_source_lines_for_node-end_line: {end_line}\n")
        	# Extract and return the lines of source code for the node
        	return '\n'.join(source_code_lines[start_line-1:end_line])
    	return "Source lines for node ID not found."

	# Example usage:
	# source_code is the Solidity source code as a string
	# ast is the AST structure as a dictionary
	# node_id is the ID of the node you are interested in
	# print(get_source_line_from_node(ast, node_id, source_code))

    def injectall(self, infile, directory, suffix):
    	# Parse Solidity source code to AST
    	infilepath = ""
    	if directory != "":
    		infilepath = directory +'/' + infile
    	else:
    		infilepath = infile
    	astConvertProblemContracts = 0
    	vulnerableContracts = 0
    	compiledVulnerableContracts = 0
    	#print(f"injectall-1\n")
    	original_ast = readastcompact(infilepath)["ast"]
    	save_to = "vul"
    	os.makedirs(save_to, exist_ok=True)
    	orig_ast_path = f"{save_to}/{infile[:-4]}_n_orig_ast_{suffix}.json"
    	writeastcompact(orig_ast_path, original_ast)
    	#print(f"injectall-2\n")
    	if original_ast != "":
    		#print(f"injectall-original_ast: {original_ast}  there is no AST\n")
    		# Find nodes where vulnerability can be injected
    		#print(f"injectall-3\n")
    		conditionPassed = self.cond(original_ast)
    		print(f"injectall-conditionPassed: {len(conditionPassed)}\n")
    		# Apply the vulnerability action to each node and update AST
    		if len(conditionPassed) == 0:
    			print(f"injectall-condition did not pass-conditionPassed: {conditionPassed}\n")
    		for node in conditionPassed:
    			#print(f"injectall-5\n")
    			ast_copy = copy.deepcopy(original_ast)
    			#print(f"injectall-6\n")
    			equivalent_node = find_node_by_id(ast_copy, node['id'])
    			#print(f"injectall-equivalent_node: {equivalent_node}\n")
    			modified_ast, operation = self.act(ast_copy, equivalent_node)
    			#print(f"injectall-modified_ast: {modified_ast}\n")
    			#print(f"injectall-7\n")
    			update_node_in_ast(ast_copy, equivalent_node['id'], modified_ast, operation)
    			#print(f"injectall-8\n")
    			vulnerable_src = convert_ast_source(ast_copy)
    			if operation == 'add':
    				vul_node_id = ast_copy['id']+1
    			else:
    				vul_node_id = node['id']
    			
    			vulnerable_src_path = f"{save_to}/{infile[:-4]}_{vul_node_id}_vul_{suffix}.sol"
    			writesourcecode(vulnerable_src_path, vulnerable_src)
    			#writeastcompact(ast_copy, new_code_path)
    			print(f"injectall-Vulnerability injected. New file saved as: {vulnerable_src_path}\n")
    			is_sucessfull= iscompilable(vulnerable_src_path)
    			print(f"injectall-if compilation of vulnerable contract is successful or not: {is_sucessfull}\n")
    			if is_sucessfull:
    				compiledVulnerableContracts += 1
    				vul_ast = readastcompact(vulnerable_src_path)["ast"]
    				#print(f"injectall-vul_ast: {vul_ast}\n")
    				vulnerable_ast_path = f"{save_to}/{infile[:-4]}_{vul_node_id}_vul_{suffix}.json"
    				#os.remove(vulnerable_src_path)
    				writeastcompact(vulnerable_ast_path, vul_ast)
    			else:
    				vulnerableContracts += 1
    				print(f"injectall-error while compiling vulnerable contract\n")
    	else:
    		astConvertProblemContracts += 1
    		print(f"injectall-error while converting original contract into Compact AST structure\n")
    	createdVulnerableContracts = compiledVulnerableContracts + vulnerableContracts
    	print(f"\nnumber of AST convert problem contract files: {astConvertProblemContracts} in {infile[:-4]} contract\n")
    	print(f"\nnumber of created vulnerable contract files: {createdVulnerableContracts} in {infile[:-4]} contract\n")
    	print(f"\nnumber of compilable created vulnerable contract files: {compiledVulnerableContracts} in {infile[:-4]} contract\n")


def mainfunc(description, condition, action, filesuffix):
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('input', type=str, help='Path to the input Solidity (.sol) or AST (.json) file')
    args = parser.parse_args()
    
    inject(args.input, condition, action, filesuffix)


