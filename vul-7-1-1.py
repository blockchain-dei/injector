#!/usr/bin/env python3

from commonc import mainfunc

'''
Vulnerability: 7-1-1 and 7-1-2 Integer Underflow and overflow source: https://openscv.dei.uc.pt/

condition function task: identify any function call of specific contract inside another contract which is assigned to a variable.

action function task: turn one statement into two independent statements.first statement is the variable part which is supposed to ba boolean and we assign "true" value to cover any kind of usage of that variable and possible business logic.
second statement would be the function call without caring about its return value. actually we assume that the function call return a boolean value. in this way we create a vulnerable contract due to not checking the return value of that specific function call.
'''

def condition(ast):
    vulnerable_nodes = []
    seen_src_locations = set()  # Track seen node src locations to avoid duplicates

    def search_node(node, context=None):
        if isinstance(node, dict):
            node_src = node.get('src')
            if node.get('nodeType') == 'FunctionDefinition':
                # Reset seen locations for each function definition to avoid cross-function contamination
                seen_src_locations.clear()
                context = {'arithmetic_vars': set(), 'assignments': {}, 'require_args': []}
                if 'body' in node and node['body'] is not None:
                	bodyNode = node['body']
                	if 'statements' in bodyNode and bodyNode['statements'] is not None:
                		for statement in node['body']['statements']:
                			search_node(statement, context)

            elif node.get('nodeType') == 'BinaryOperation' and node['operator'] in ['+', '-', '*', '/'] and context is not None:
                # Track variables involved in arithmetic operations
                process_arithmetic_operation(node, context)

            elif node.get('nodeType') == 'ExpressionStatement':
                # Check if it's an assignment resulting from an arithmetic operation
                expression = node.get('expression')
                if expression and expression.get('nodeType') == 'Assignment':
                    process_assignment(expression, context)

            elif node.get('nodeType') == 'FunctionCall':
                expression_name = node.get('expression', {}).get('expression', {}).get('name') or node.get('expression', {}).get('name')
                if expression_name in ['require', 'assert'] and context and 'arguments' in node and len(node['arguments']) > 0:
                    condition = node['arguments'][0]
                    condition_src = condition.get('src')
                    if matches_arithmetic_vars_or_assignments(condition, context) and condition_src not in seen_src_locations:
                        vulnerable_nodes.append(condition)  # Append only the condition node
                        seen_src_locations.add(condition_src)  # Remember this src location

            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    search_node(value, context)

        elif isinstance(node, list):
            for item in node:
                search_node(item, context)

    def process_arithmetic_operation(node, context):
        left_var = node['leftExpression'].get('name')
        right_var = node['rightExpression'].get('name')
        if left_var and right_var:
            context['arithmetic_vars'].update([left_var, right_var])

    def process_assignment(node, context):
        var_name = node['leftHandSide'].get('name')
        if 'rightHandSide' in node and node['rightHandSide'].get('nodeType') == 'BinaryOperation':
            left_var = node['rightHandSide']['leftExpression'].get('name')
            right_var = node['rightHandSide']['rightExpression'].get('name')
            if left_var and right_var:
                context['assignments'][var_name] = {left_var, right_var}

    def matches_arithmetic_vars_or_assignments(node, context):
        if node.get('nodeType') == 'BinaryOperation':
            left_var = node['leftExpression'].get('name')
            right_var = node['rightExpression'].get('name')
            # Check for direct matches with arithmetic vars
            direct_match = left_var in context['arithmetic_vars'] and right_var in context['arithmetic_vars']
            # Check for matches with assignments
            assignment_match = any(left_var in vars or right_var in vars for vars in context['assignments'].values())
            return direct_match or assignment_match
        return False

    search_node(ast)
    print(f"condition vulnerable_nodes_count: {len(vulnerable_nodes)}")
    return vulnerable_nodes

def conditionold5(ast):
    vulnerable_nodes = []

    def search_node(node, context=None):
        if isinstance(node, dict):
            if node.get('nodeType') == 'FunctionDefinition':
                # Extend context to track assignments from arithmetic operations
                context = {'arithmetic_vars': set(), 'assignments': {}, 'require_args': []}
                for statement in node['body']['statements']:
                    search_node(statement, context)
            
            elif node.get('nodeType') == 'BinaryOperation' and node['operator'] in ['+', '-', '*', '/'] and context is not None:
                # Process arithmetic operation and track variables involved
                process_arithmetic_operation(node, context)

            elif node.get('nodeType') == 'ExpressionStatement':
                # Handle cases where the result of an arithmetic operation is assigned to a variable
                expression = node.get('expression')
                if expression and expression.get('nodeType') == 'Assignment':
                    process_assignment(expression, context)

            elif node.get('nodeType') == 'FunctionCall':
                expression_name = node.get('expression', {}).get('expression', {}).get('name')
                if expression_name in ['require', 'assert'] and context and 'arguments' in node and node['arguments']:
                    # Check if variables or results in require/assert match those involved in arithmetic operations
                    condition = node['arguments'][0]
                    if matches_arithmetic_vars_or_assignments(condition, context):
                        vulnerable_nodes.append(condition)  # Append only the condition node of require/assert

            # Recursively search child nodes
            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    search_node(value, context)

        elif isinstance(node, list):
            for item in node:
                search_node(item, context)

    def process_arithmetic_operation(node, context):
        left_var = node['leftExpression'].get('name')
        right_var = node['rightExpression'].get('name')
        if left_var and right_var:
            context['arithmetic_vars'].update([left_var, right_var])

    def process_assignment(node, context):
        if node.get('rightHandSide', {}).get('nodeType') == 'BinaryOperation':
            var_name = node['leftHandSide'].get('name')
            left_var = node['rightHandSide']['leftExpression'].get('name')
            right_var = node['rightHandSide']['rightExpression'].get('name')
            context['assignments'][var_name] = {'left': left_var, 'right': right_var}

    def matches_arithmetic_vars_or_assignments(node, context):
        if node.get('nodeType') == 'BinaryOperation':
            left_var = node['leftExpression'].get('name')
            right_var = node['rightExpression'].get('name')
            # Check direct arithmetic variable matches
            vars_match = left_var in context['arithmetic_vars'] and right_var in context['arithmetic_vars']

            # Check for matches with assignments
            assignments_match = any(left_var in pair.values() and right_var in pair.values() for pair in context['assignments'].values())
            
            return vars_match or assignments_match
        return False

    search_node(ast)
    print(f"condition vulnerable_nodes_count: {len(vulnerable_nodes)}")
    return vulnerable_nodes

def conditionold4(ast):
    vulnerable_nodes = []

    def search_node(node, context=None):
        if isinstance(node, dict):
            if node.get('nodeType') == 'FunctionDefinition':
                # Extend context to track assignments from arithmetic operations
                context = {'arithmetic_vars': set(), 'assignments': {}, 'require_args': []}
                for statement in node['body']['statements']:
                    search_node(statement, context)
            
            elif node.get('nodeType') == 'BinaryOperation' and node['operator'] in ['+', '-', '*', '/'] and context is not None:
                # Process arithmetic operation and track variables involved
                process_arithmetic_operation(node, context)

            elif node.get('nodeType') == 'VariableDeclarationStatement':
                # Handle cases where the result of an arithmetic operation is assigned to a variable
                process_variable_declaration(node, context)

            elif node.get('nodeType') == 'FunctionCall':
                expression_name = node.get('expression', {}).get('name')
                if expression_name in ['require', 'assert'] and context and 'arguments' in node and node['arguments']:
                    # Check if variables or results in require/assert match those involved in arithmetic operations
                    condition = node['arguments'][0]
                    if matches_arithmetic_vars_or_assignments(condition, context):
                        vulnerable_nodes.append(condition)  # Append only the condition node of require/assert

            # Recursively search child nodes
            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    search_node(value, context)

        elif isinstance(node, list):
            for item in node:
                search_node(item, context)

    def process_arithmetic_operation(node, context):
        left_var = node['leftExpression'].get('name')
        right_var = node['rightExpression'].get('name')
        if left_var and right_var:
            context['arithmetic_vars'].update([left_var, right_var])

    def process_variable_declaration(node, context):
        if 'initialValue' in node and node['initialValue'].get('nodeType') == 'BinaryOperation':
            var_name = node['declarations'][0].get('name')
            context['assignments'][var_name] = {'leftExpression': node['initialValue']['leftExpression'].get('name'), 'rightExpression': node['initialValue']['rightExpression'].get('name')}

    def matches_arithmetic_vars_or_assignments(node, context):
    	if node.get('nodeType') == 'BinaryOperation':
        	left_var = node['leftExpression'].get('name')
        	right_var = node['rightExpression'].get('name')
        	# Check direct arithmetic variable matches
        	vars_match = left_var in context['arithmetic_vars'] and right_var in context['arithmetic_vars']

	        # Corrected logic for assignment matches
        	assignments_match_left = left_var in context['assignments'] and \
            	(context['assignments'][left_var].get('left') == right_var or context['assignments'][left_var].get('right') == right_var)
        	assignments_match_right = False
        	for assignment, vars in context['assignments'].items():
        		if right_var == assignment and (left_var == vars.get('left') or left_var == vars.get('right')):
        			assignments_match_right = True
        			break

        	assignments_match = assignments_match_left or assignments_match_right
        	return vars_match or assignments_match
    	return False


    search_node(ast)
    print(f"condition vulnerable_nodes_count: {len(vulnerable_nodes)}")
    return vulnerable_nodes

def conditionold3(ast):
    vulnerable_nodes = []

    def search_node(node, context=None):
        if isinstance(node, dict):
            if node.get('nodeType') == 'FunctionDefinition':
                # Reset context when entering a new function definition
                context = {'arithmetic_vars': set(), 'require_args': []}
                for statement in node['body']['statements']:
                    search_node(statement, context)
            
            elif node.get('nodeType') == 'BinaryOperation' and node['operator'] in ['+', '-', '*', '/'] and context is not None:
                # Capture variable names involved in arithmetic operations
                left_var = node['leftExpression'].get('name')
                right_var = node['rightExpression'].get('name')
                if left_var and right_var:
                    context['arithmetic_vars'].update([left_var, right_var])

            elif node.get('nodeType') == 'FunctionCall':
                expression_name = node.get('expression', {}).get('name')
                if expression_name in ['require', 'assert'] and context and 'arguments' in node and node['arguments']:
                    # Check if variables in require/assert match those in arithmetic operations
                    condition = node['arguments'][0]
                    if matches_arithmetic_vars(condition, context['arithmetic_vars']):
                        vulnerable_nodes.append(node['arguments'][0])  # Append only the condition node of require/assert

            # Recursively search child nodes
            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    search_node(value, context)

        elif isinstance(node, list):
            for item in node:
                search_node(item, context)

    def matches_arithmetic_vars(node, arithmetic_vars):
        # Check if the node (condition of require/assert) uses the same vars as the arithmetic operation
        if node.get('nodeType') == 'BinaryOperation':
            left_var = node['leftExpression'].get('name')
            right_var = node['rightExpression'].get('name')
            return left_var in arithmetic_vars and right_var in arithmetic_vars
        return False

    search_node(ast)
    return vulnerable_nodes

def conditionold2(ast):
    # Function to return nodes that contain the specific pattern of vulnerability
    vulnerable_nodes = []

    # Define a helper function to recursively search for patterns within functions
    def search_node(node, search_for_arithmetic=False):
        # Ensure node is a dictionary and has 'nodeType' key
        if isinstance(node, dict) and 'nodeType' in node:
            # If node is a function definition, check its body
            if node['nodeType'] == 'FunctionDefinition':
                has_arithmetic = any(search_node(child, True) for child in node['body']['statements'])
                has_require_or_assert = any(search_node(child) for child in node['body']['statements'])
                if has_arithmetic and has_require_or_assert:
                    vulnerable_nodes.append(node)  # Append the function node if it contains both patterns
                return False  # Stop searching deeper in this branch

            # Searching for arithmetic operations
            if search_for_arithmetic and node['nodeType'] in ['BinaryOperation'] and node['operator'] in ['+', '-', '*', '/']:
                return True

            # Searching for require or assert with a specific condition
            if not search_for_arithmetic and node['nodeType'] in ['FunctionCall'] and 'expression' in node and node['expression'].get('name') in ['require', 'assert']:
                # Simplified check for b >= a pattern
                if 'arguments' in node and node['arguments'] and node['arguments'][0].get('nodeType') == 'BinaryOperation' and node['arguments'][0].get('operator') == '>=':
                    return True

        # Recursively search in child nodes if the node is a dictionary or list
        if isinstance(node, dict):
            for value in node.values():
                if search_node(value, search_for_arithmetic):
                    return True
        elif isinstance(node, list):
            for item in node:
                if search_node(item, search_for_arithmetic):
                    return True
        return False

    # Start the search from the root node
    search_node(ast)
    print(f"\n\ncondition result: {vulnerable_nodes}\n\n")
    return vulnerable_nodes

def conditionold(ast):
    matches = []

    def traverse(node, parent=None):
        if isinstance(node, dict):
            if (node.get('nodeType') == 'FunctionCall' and
                node.get('expression', {}).get('nodeType') == 'Identifier' and
                node['expression'].get('name') in ['sub', 'add']):
                # Check if the parent node is an Assignment
                if parent and parent.get('nodeType') == 'Assignment':
                    matches.append(parent)  # Add the assignment node
            else:
                for value in node.values():
                    traverse(value, node)
        elif isinstance(node, list):
            for item in node:
                traverse(item, parent)

    traverse(ast)
    return matches


def action(ast, vulnerable_node):
    # Build a "true" statement node
    operation_type = None
    true_statement = {
        "nodeType": "Literal",
        "value": "true",
        "typeDescriptions": {
            "typeIdentifier": "t_bool",
            "typeString": "bool"
        }
    }
    # Assuming vulnerable_node is a require or assert, replace its condition with true_statement
    # This is simplified; in practice, you might need to navigate to the specific require/assert node
    return [true_statement], operation_type
    
def actionold(ast, target_node):
    modified_nodes = []
    right_hand_side = target_node.get('rightHandSide', {})

    # Determine the new operator based on the function name
    if right_hand_side.get('expression', {}).get('name') == 'sub':
        new_operator = '-='
    elif right_hand_side.get('expression', {}).get('name') == 'add':
        new_operator = '+='
    else:
        return []

    # Construct the modified assignment
    modified_assignment = {
        "nodeType": target_node['nodeType'],
        "src": target_node['src'],
        "id": target_node['id'],
        "operator": new_operator,
        "leftHandSide": target_node['leftHandSide'],
        "rightHandSide": right_hand_side['arguments'][1],  # The second argument of the function call
    }

    modified_nodes.append(modified_assignment)
    return modified_nodes

if __name__ == "__main__":
    mainfunc('7-1-1', condition, action, '7-1-1')