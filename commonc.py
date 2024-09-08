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


