#!/usr/bin/env python3

from commonc import mainfunc

'''
Vulnerability: 6.2.1 Improper Input Validation source: https://openscv.dei.uc.pt/

condition function task: find msg.data.length

action function task: replace it with True
'''

def condition(ast):
    """
    Searches for instances where msg.data.length is checked against a condition.
    """
    checks = []

    def traverse(node):
        if isinstance(node, dict):
            # Look for BinaryOperation nodes with a specific pattern
            if node.get('nodeType') == 'BinaryOperation' and \
                'leftExpression' in node and \
                node['leftExpression'].get('nodeType') == 'MemberAccess' and \
                node['leftExpression'].get('memberName') == 'length' and \
                node['leftExpression']['expression'].get('memberName') == 'data' and \
                node['leftExpression']['expression'].get('expression', {}).get('name') == 'msg':
                    checks.append(node)
            else:
                # Recursively search in all dictionary values
                for key, value in node.items():
                    traverse(value)
        elif isinstance(node, list):
            # Recursively search in all list items
            for item in node:
                traverse(item)

    traverse(ast)
    print(f"condition-6-2-1-checks: {checks}")
    return checks


def action(ast, check_node):
    """
    Modifies the AST node or context to replace checks involving msg.data.length
    with a 'true' literal expression.
    """
    operation_type = None
    modified_nodes = []

    # Construct a 'true' literal node
    true_node = {
        "nodeType": "Literal",
        "value": "true",
        "typeDescriptions": {
            "typeIdentifier": "t_bool",
            "typeString": "bool"
        }
    }
    modified_nodes.append(true_node)
    return modified_nodes, operation_type
    
def actionold(ast, target_function):
    """
    Modifies the given function by adding a recursive call to it.
    """
    print(f"\n\naction-6-2-1-target_function: {target_function}\n\n")
    function_name = target_function.get("name")
    print(f"\n\naction-6-2-1-function_name: {function_name}\n\n")
    recursive_call = {
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
    if "body" in target_function and "statements" in target_function["body"]:
        target_function["body"]["statements"].insert(1, recursive_call)  # Insert after the first statement
    
    return [target_function]


if __name__ == "__main__":
    mainfunc('6-2-1', condition, action, '6-2-1')