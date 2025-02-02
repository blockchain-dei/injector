#!/usr/bin/env python3

from common import mainfunc

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
    

if __name__ == "__main__":
    mainfunc('7-1-1', condition, action, '7-1-1')