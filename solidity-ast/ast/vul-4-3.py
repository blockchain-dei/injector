#!/usr/bin/env python3

from common import mainfunc

'''
Vulnerability: 4.3 Wrong use of Transfer Credit Function source: https://openscv.dei.uc.pt/

condition function task: msg.sender.transfer(refund);

action function task: msg.sender.call.value(refund)("");
'''

def is_target_call_value(node):
    
    if node.get('nodeType') == 'ExpressionStatement':
        expression = node.get('expression', {})
        if expression.get('nodeType') == 'FunctionCall':
            outer_expression = expression.get('expression', {})
            if outer_expression.get('nodeType') == 'MemberAccess':
                member_name = outer_expression.get('memberName', '')
                if member_name in ['transfer', 'call']:
                    sender_expression = outer_expression.get('expression', {})
                    if sender_expression.get('nodeType') == 'MemberAccess' and sender_expression.get('memberName') == 'sender':
                        msg_expression = sender_expression.get('expression', {})
                        if msg_expression.get('nodeType') == 'Identifier' and msg_expression.get('name') == 'msg':
                            return True
    return False

def condition(ast):

    matches = []
 
    def traverse(node):
        # Recursively traverse the AST to find nodes
        if isinstance(node, dict):
            if is_target_call_value(node):
                matches.append(node)
            for value in node.values():
                if isinstance(value, (dict, list)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)

    traverse(ast)
    return matches

def action(ast, target_node):
    operation_type = None
    expression = target_node.get('expression', {})

    new_exp = {
        "argumentTypes" : 
		[
			{
				"typeIdentifier" : "t_uint256",
				"typeString" : "uint256"
			}
		],
        "expression" :
        {
            "expression" : 
            {
                "expression" : 
                {
                    "argumentTypes" : None,
                    "name" : "msg",
                    "nodeType" : "Identifier",
                },
                "isConstant" : False,
                "isLValue" : False,
                "isPure" : False,
                "lValueRequested" : False,
                "memberName" : "sender",
                "nodeType" : "MemberAccess",
                "referencedDeclaration" : None,
            },
            "isConstant" : False,
            "isLValue" : False,
            "isPure" : False,
            "lValueRequested" : False,
            "memberName" : "call",
            "nodeType" : "MemberAccess",
            "referencedDeclaration" : None,
        },
        "isConstant" : False,
        "isLValue" : False,
        "isPure" : False,
        "lValueRequested" : False,
        "memberName" : "value",
        "nodeType" : "MemberAccess",
        "referencedDeclaration" : None,
    }

    if expression.get('nodeType') == 'FunctionCall':
        member_access = expression.get('expression', {})
        if member_access.get('nodeType') == 'MemberAccess':
            target_node['expression']['expression'] = new_exp
            #target_node['expression']['argumentTypes'] = new_typ
            
    return target_node, operation_type

if __name__ == "__main__":
    mainfunc('4-3', condition, action, '4-3')