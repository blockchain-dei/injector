#!/usr/bin/env python3

from common import mainfunc

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
    

if __name__ == "__main__":
    mainfunc('6-2-1', condition, action, '6-2-1')