#!/usr/bin/env python3

from commonc import mainfunc

'''
Vulnerability: 1.3.2 Improper Exception Handling of External Calls source: https://openscv.dei.uc.pt/

condition function task: identify any function call of specific contract inside another contract which is assigned to a variable.

action function task: turn one statement into two independent statements.first statement is the variable part which is supposed to ba boolean and we assign "true" value to cover any kind of usage of that variable and possible business logic.
second statement would be the function call without caring about its return value. actually we assume that the function call return a boolean value. in this way we create a vulnerable contract due to not checking the return value of that specific function call.
'''

def condition(ast):
    contract_names = get_contract_names(ast)
    if_conditions = []

    def traverse(node):
        if isinstance(node, dict):
            # Check for if statements
            if node.get('nodeType') == 'IfStatement':
                condition = node.get('condition')
                # Check if the condition involves an object of any known contract
                if condition and any(contract_name in str(condition) for contract_name in contract_names):
                    if_conditions.append(node)
            # Traverse further into the node
            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)

    traverse(ast)
    return if_conditions

def get_contract_names(ast):
    return [node['name'] for node in ast.get('nodes', []) if node['nodeType'] == 'ContractDefinition']


def action(ast, target_node):
    """
    Modifies the if condition node to retain only the true body of the if statement
    and ensures the returned structure is always a list.
    """
    operation_type = None
    true_body = target_node.get('trueBody')

    # Ensure the true body is wrapped in a list
    if true_body:
        # Check if the true body is already a list or a single statement
        if isinstance(true_body, dict):
            # If it's a single statement (dict), wrap it in a list
            true_body = [true_body]
        elif isinstance(true_body, list):
            # If it's already a list, it's fine as is
            pass
        else:
            # If true body is in an unexpected format, initialize as an empty list
            true_body = []

    # Optionally, wrap in an additional block if necessary
    # true_body = [{'nodeType': 'Block', 'statements': true_body}]

    print(f"action-true_body: {true_body}")
    return true_body, operation_type
    
def actionold(ast, target_node):
    """
    Removes the if condition and retains only the true body of the if statement.
    """
    true_body = target_node.get('trueBody')
    # Convert the true body to an expression statement if it's not already one
    if true_body and 'nodeType' not in true_body:
        true_body = {'nodeType': 'Block', 'statements': true_body}
    print(f"action-true_body: {true_body}")
    return true_body

if __name__ == "__main__":
    mainfunc('1-3-2', condition, action, '1-3-2')