import pandas
import argparse
import os

#################
# CLI INTERFACE #
#################

parser = argparse.ArgumentParser(description='Derives Sankey data from an aggregated CSV')

parser.add_argument('input', help='the path of the aggregated CSV')
parser.add_argument('-l', '--delimiter', metavar='char', default=',', help='delimiter character of the CSVs')

args = parser.parse_args()

############
# READ CSV #
############

print(f'Reading aggregated CSV: {args.input}')
df = pandas.read_csv(args.input, low_memory=False, delimiter=args.delimiter)

# filter for interesting columns
df = df[['ID_contract_filename', 'ID_protection_type', 'ID_faulty_contract', 'ID_duplicate_contract', 'FORMAL_result',
         'TX_data_integrity_error', 'TX_reliability_error', 'TX_accessibility_error', 'TX_hidden_side_effect',
         'TX_execution_fullmatch', 'ERROR_is_application_level', 'ERROR_is_platform_level', 'ERROR_is_timeout',
         'ERROR_is_fabric_timeout', 'ERROR_is_evm_timeout', 'ERROR_is_assert', 'ERROR_is_require', 'ERROR_is_balance',
         'ERROR_is_modify_nonexistent_account', 'ERROR_is_create_account_permission', 'ERROR_is_fabric_level',
         'ERROR_is_evm_level', 'ENDORSE_any_error', 'TX_commit_match_error']]

# filter for faulty contracts
df = df[df['ID_faulty_contract'] & ~df['ID_duplicate_contract']]

# Sankey nodes
sk_faultload = 'Faultload'
sk_verification_detect = 'Verification Detect'
sk_contract_self_check = 'Contract Self-check'
sk_contract_detect = 'Contract Detect'
sk_assert_detect = 'Assert Detect'
sk_runtime_platform_check = 'Runtime Platform Check'
sk_runtime_platform_detect = 'Runtime Platform Detect'
sk_output_invariant_check = 'Output Invariant Check'
sk_client_observable_failure = 'Client Observable failure'
sk_undetected = 'Undetected'
sk_ineffective = 'Ineffective'
sk_latent_ledger_integrity_error = 'Latent Ledger Integrity Error'


def create_entry(row, from_, to):
    return {
        'ID_contract_filename': row['ID_contract_filename'],
        'ID_protection_type': row['ID_protection_type'],
        'ID_duplicate_contract': row['ID_duplicate_contract'],
        'FORMAL_result': row['FORMAL_result'],
        'TX_accessibility_error': row['TX_accessibility_error'],
        'TX_reliability_error': row['TX_reliability_error'],
        'TX_hidden_side_effect': row['TX_hidden_side_effect'],
        'TX_data_integrity_error': row['TX_data_integrity_error'],
        'ERROR_is_application_level': row['ERROR_is_application_level'],
        'ERROR_is_platform_level': row['ERROR_is_platform_level'],
        'ERROR_is_timeout': row['ERROR_is_timeout'],
        'ERROR_is_fabric_timeout': row['ERROR_is_fabric_timeout'],
        'ERROR_is_evm_timeout': row['ERROR_is_evm_timeout'],
        'ERROR_is_assert': row['ERROR_is_assert'],
        'ERROR_is_require': row['ERROR_is_require'],
        'ERROR_is_balance': row['ERROR_is_balance'],
        'ERROR_is_modify_nonexistent_account': row['ERROR_is_modify_nonexistent_account'],
        'ERROR_is_create_account_permission': row['ERROR_is_create_account_permission'],
        'ERROR_is_fabric_level': row['ERROR_is_fabric_level'],
        'ERROR_is_evm_level': row['ERROR_is_evm_level'],
        'ENDORSE_any_error': row['ENDORSE_any_error'],
        'TX_commit_match_error': row['TX_commit_match_error'],
        'TX_execution_fullmatch': row['TX_execution_fullmatch'],
        'from': from_,
        'to': to
    }


def create_after_verif_flow(entries, row, assert_detect=False):
    # Faultload => Contract Self-check
    entries.append(create_entry(row, sk_faultload, sk_contract_self_check))

    # Contract Self-check => Contract Detect
    if (not row['TX_commit_match_error']) and row['ERROR_is_application_level']:
        entries.append(create_entry(row, sk_contract_self_check, sk_contract_detect))
        if assert_detect and row['ERROR_is_assert']:
            entries.append(create_entry(row, sk_contract_detect, sk_assert_detect))
        return

    # Contract Self-check => Runtime Platform Check
    entries.append(create_entry(row, sk_contract_self_check, sk_runtime_platform_check))

    # Runtime Platform Check => Runtime Platform Detect
    if (not row['TX_commit_match_error']) and row['ERROR_is_platform_level']:
        entries.append(create_entry(row, sk_runtime_platform_check, sk_runtime_platform_detect))
        return

    # Runtime Platform Check => Output Invariant Check
    entries.append(create_entry(row, sk_runtime_platform_check, sk_output_invariant_check))

    # Output Invariant Check => Client Observable failure
    if row['TX_reliability_error']:
        entries.append(create_entry(row, sk_output_invariant_check, sk_client_observable_failure))
        return

    # Output Invariant Check => Undetected
    entries.append(create_entry(row, sk_output_invariant_check, sk_undetected))

    if row['TX_hidden_side_effect'] or row['TX_data_integrity_error']:
        entries.append(create_entry(row, sk_undetected, sk_latent_ledger_integrity_error))
    elif row['TX_execution_fullmatch']:
        entries.append(create_entry(row, sk_undetected, sk_ineffective))
    else:
        entries.append(create_entry(row, sk_undetected, 'NOT CATEGORIZED!!!'))


def construct_sankey(dataframe, file_path, include_verif, include_assert):
    sankey_entries = []

    for index, row in dataframe.iterrows():
        if include_verif:
            # Faultload => Verification Detect
            if row['FORMAL_result'] is False or row['FORMAL_result'] == 'FALSE':
                sankey_entries.append(create_entry(row, sk_faultload, sk_verification_detect))
                continue

        create_after_verif_flow(sankey_entries, row, include_assert)

    sankey_df = pandas.DataFrame(sankey_entries)
    print(f'Saving {file_path}')
    sankey_df.to_csv(file_path, index=False, sep=',')


output_dir = os.path.dirname(args.input)

print(f'Constructing Sankey (verification, assert)')
construct_sankey(df, f'{output_dir}/SANKEY_VERIF_ASSERT.csv', True, True)

print(f'Constructing Sankey (no verification, no assert)')
construct_sankey(df, f'{output_dir}/SANKEY_NO_VERIF_NO_ASSERT.csv', False, False)

print(f'Constructing Sankey (verification, no assert)')
construct_sankey(df, f'{output_dir}/SANKEY_VERIF_NO_ASSERT.csv', True, False)

print(f'Constructing Sankey (no verification, assert)')
construct_sankey(df, f'{output_dir}/SANKEY_NO_VERIF_ASSERT.csv', False, True)
