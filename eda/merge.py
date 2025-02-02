import os
import pandas
import sys
import glob
import argparse
import yaml
import gc

 

def load_yaml(file):
    with open(file, 'r') as stream:
        try:
            return yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(f'Couldn\'t load YAML file {file}')
            print(exc)
            sys.exit(1)


#################
# CLI INTERFACE #
#################
parser = argparse.ArgumentParser(description='Collects multiple transaction data CSV into a single CSV')

parser.add_argument('input', help='the directory containing the TX CSVs to combine')
parser.add_argument('-v', '--formal', help='the directory containing the formal verification CSVs to combine',
                    default='')
parser.add_argument('-o', '--output', metavar='file', default='./', help='the directory for the output files')
parser.add_argument('-c', '--contracts', default='./../metadata/contracts.csv', help='the contract metadata CSV file')
parser.add_argument('-f', '--faults', default='./../metadata/faults.csv', help='the fault metadata CSV file')
parser.add_argument('-d', '--duplicates', default='./../metadata/duplicates.csv', help='the duplicates CSV file')
parser.add_argument('-l', '--delimiter', metavar='char', default=';', help='delimiter character of the CSVs')

args = parser.parse_args()

###############
# GLOBAL VARS #
###############
long_tx_header = ['tx_id', 'variable', 'value']  # the common header for the long format
tx_input_search_pattern = '{0}/*.csv'.format(args.input)

tx_input_csvs = glob.glob(tx_input_search_pattern, recursive=False)
tx_input_csvs.sort()

if len(tx_input_csvs) == 0:
    print('''Search pattern '{0}' didn't match any input files'''.format(tx_input_search_pattern))
    sys.exit(1)

if len(tx_input_csvs) == 0:
    print('''Search pattern '{0}' didn't match any input files'''.format(tx_input_search_pattern))
    sys.exit(1)

output_dir = os.path.dirname(args.output)  # output directory for the new CSVs
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

col_rename = load_yaml('./configs/col_rename.yaml')
col_order = load_yaml('./configs/col_order.yaml')

#####################
# PROCESSING TX CSV #
#####################

tx_long_dfs = []
print(f'Reading {len(tx_input_csvs)} TX result CSVs...')
for csv_file in tx_input_csvs:
    try:
        file_name = os.path.splitext(os.path.basename(csv_file))[0]
        df = pandas.read_csv(csv_file, header=None, names=long_tx_header, low_memory=False, delimiter=args.delimiter)
        tx_long_dfs.append(df)
    except Exception as e:
        print(csv_file + " has some error: " + str(e))
        pass

print('Concatenating and pivoting...')
tx_wide_df = pandas.concat(tx_long_dfs, ignore_index=False).pivot(index='tx_id', columns='variable', values='value')
tx_wide_df.reset_index(level=0, inplace=True)

del tx_long_dfs
gc.collect()

print('Reading and merging metadata...')
faults_metadata_df = pandas.read_csv(args.faults, low_memory=False, delimiter=args.delimiter)
contracts_metadata_df = pandas.read_csv(args.contracts, low_memory=False, delimiter=args.delimiter)
duplicates_metadata_df = pandas.read_csv(args.duplicates, low_memory=False, delimiter=args.delimiter)

tx_wide_df = tx_wide_df.merge(contracts_metadata_df, how='left', on='contract_name')
tx_wide_df = tx_wide_df.merge(duplicates_metadata_df, how='left', on='contract_name')
tx_wide_df = tx_wide_df.merge(faults_metadata_df, how='left', on='odc_fault_id')


print('Converting time columns to numbers...')
time_columns = [col for col in tx_wide_df.columns if col.startswith('time_') or col.startswith('commit_failure_') or
                col.startswith('commit_success_') or col.startswith('duration_ns_')
                or col.startswith('cc_end_epoch_')]
for col in time_columns:
    if col.startswith('cc_end_epoch_'):  # to prevent cells from being outputed as scientific notation to the csv
        tx_wide_df[col] = tx_wide_df[col].astype("string")
    else:
        tx_wide_df[col] = pandas.to_numeric(tx_wide_df[col], errors='coerce')

print('Calculating relative time offsets...')
time_offsets = {}
for index, row in contracts_metadata_df.iterrows():
    contract_selector = tx_wide_df['contract_id'] == row['contract_id']
    contract_rows = tx_wide_df.loc[contract_selector, 'time_create']

    if len(contract_rows) < 1:
        continue

    min_time_row = tx_wide_df.loc[[contract_rows.idxmin()]]

    if len(min_time_row) < 1:
        print('Couldn\'t determine minimum create time for {0}'.format(row['contract_name']))
        continue

    min_time = min_time_row.iloc[0]['time_create']
    time_offsets[row['contract_id']] = min_time

gc.collect()
print('Renaming exotic strings...')
error_rename = load_yaml('./configs/error_rename.yaml')
for orig, new in error_rename.items():
    tx_wide_df.replace(to_replace=orig, value=new, inplace=True, regex=True)

print('Deriving additional variables...')
gc.collect()

#print(tx_wide_df['contract_name'])

# some flag variables

try:
  tx_wide_df['blockchain_specific_fault'] = tx_wide_df['odc_fault_id'].astype(int) >= 63 
except Exception as e:
  print(tx_wide_df['contract_name'] + " has some error: " + str(e))

#tx_wide_df['blockchain_specific_fault'] = tx_wide_df['odc_fault_id'].astype(int) >= 63


tx_wide_df['read_set_empty'] = (tx_wide_df['reads'] == '') | (pandas.isnull(tx_wide_df['reads']))
tx_wide_df['write_set_empty'] = (tx_wide_df['writes'] == '') | (pandas.isnull(tx_wide_df['writes']))
tx_wide_df['faulty_contract'] = tx_wide_df['contract_id'] != tx_wide_df['reference_contract']

# timestamps to durations
tx_wide_df['duration_ms_endorse'] = tx_wide_df['time_endorse'] - tx_wide_df['time_create']
tx_wide_df['duration_ms_total'] = tx_wide_df['time_final'] - tx_wide_df['time_create']
tx_wide_df['duration_ms_order_and_validate'] = tx_wide_df['duration_ms_total'] - tx_wide_df['duration_ms_endorse']

# add helper column storing the time offsets for each contract


try:
  tx_wide_df['rel_time_offset'] = tx_wide_df.apply(lambda row: time_offsets[row['contract_id']], axis=1)
except Exception as e:
  tx_wide_df['rel_time_offset']=0
  print(tx_wide_df['contract_id'])
  print("error: " + str(e))

#tx_wide_df['rel_time_offset'] = tx_wide_df.apply(lambda row: time_offsets[row['contract_id']], axis=1)

# relative timestamps
tx_wide_df['time_create_rel'] = tx_wide_df['time_create'] - tx_wide_df['rel_time_offset']
tx_wide_df['time_endorse_rel'] = tx_wide_df['time_endorse'] - tx_wide_df['rel_time_offset']
tx_wide_df['time_orderer_ack_rel'] = tx_wide_df['time_orderer_ack'] - tx_wide_df['rel_time_offset']
tx_wide_df['time_final_rel'] = tx_wide_df['time_final'] - tx_wide_df['rel_time_offset']

tx_wide_df['ENDORSE_any_error'] = pandas.notnull(
    tx_wide_df['proposal_response_error_peer0.org1.example.com']) | pandas.notnull(
    tx_wide_df['proposal_response_error_peer0.org2.example.com'])

tx_wide_df['ID_mutation_variant_id'] = tx_wide_df.apply(
    lambda r: f'{r["odc_fault_id"]}.{r["odc_fault_variant"]}', axis=1)

tx_wide_df['ID_mutation_variant_name'] = tx_wide_df.apply(
    lambda r: f'{r["odc_fault_name"]}.{r["odc_fault_variant"]}', axis=1)

gc.collect()
print('Assembling master frame with reference transactions...')

df_copy = tx_wide_df.copy(deep=True)
print('passei')


tx_wide_df.set_index(['reference_contract','tx_index'])
df_copy.set_index(['contract_id','tx_index'])

# merge the corresponding reference transaction next to every transaction, and add the _REF suffix to the ref TX columns

#tx_master_df = pandas.merge(tx_wide_df, df_copy, how='left', left_on=['reference_contract', 'tx_index'],
#                            right_on=['contract_id', 'tx_index'], suffixes=('', '_REF'),copy=False)

tx_master_df = pandas.merge(tx_wide_df, df_copy, how='left', left_index=True,
                            right_index=True, suffixes=('', '_REF'))

del tx_wide_df
del df_copy
gc.collect()
print('Comparing transactions to their reference...')
# delta times compared to the reference time (current Tx "time" - ref Tx "time)
tx_master_df['refdelta_duration_ns_cc_peer0.org1.example.com'] = \
    tx_master_df['duration_ns_cc_peer0.org1.example.com'] - tx_master_df['duration_ns_cc_peer0.org1.example.com_REF']

tx_master_df['refdelta_duration_ns_cc_peer0.org2.example.com'] = \
    tx_master_df['duration_ns_cc_peer0.org2.example.com'] - tx_master_df['duration_ns_cc_peer0.org2.example.com_REF']

tx_master_df['refdelta_duration_ns_evm_peer0.org1.example.com'] = \
    tx_master_df['duration_ns_evm_peer0.org1.example.com'] - tx_master_df['duration_ns_evm_peer0.org1.example.com_REF']

tx_master_df['refdelta_duration_ns_evm_peer0.org2.example.com'] = \
    tx_master_df['duration_ns_evm_peer0.org2.example.com'] - tx_master_df['duration_ns_evm_peer0.org2.example.com_REF']

tx_master_df['refdelta_duration_ms_total'] = tx_master_df['duration_ms_total'] - tx_master_df['duration_ms_total_REF']

tx_master_df['refdelta_duration_ms_endorse'] = \
    tx_master_df['duration_ms_endorse'] - tx_master_df['duration_ms_endorse_REF']

tx_master_df['refdelta_duration_ms_order_and_validate'] = \
    tx_master_df['duration_ms_order_and_validate'] - tx_master_df['duration_ms_order_and_validate_REF']


# TX result correctness checks
def correct_match(ref_out, out):
    return (ref_out == out) | ((ref_out != ref_out) & (out != out))


tx_master_df['TX_ref_success'] = tx_master_df['status_REF'] == 'success'
tx_master_df['matches_return_value'] = correct_match(tx_master_df['return_value_REF'], tx_master_df['return_value'])
tx_master_df['matches_read_set'] = correct_match(tx_master_df['reads_REF'], tx_master_df['reads'])
tx_master_df['matches_write_set'] = correct_match(tx_master_df['writes_REF'], tx_master_df['writes'])
tx_master_df['matches_status'] = correct_match(tx_master_df['status_REF'], tx_master_df['status'])
tx_master_df['matches_error'] = correct_match(tx_master_df['proposal_response_error_peer0.org1.example.com_REF'],
                                              tx_master_df['proposal_response_error_peer0.org1.example.com']) & \
                                correct_match(tx_master_df['proposal_response_error_peer0.org2.example.com_REF'],
                                              tx_master_df['proposal_response_error_peer0.org2.example.com'])

tx_master_df['matches_reference_tx'] = tx_master_df['matches_return_value'] & \
                                       tx_master_df['matches_read_set'] & \
                                       tx_master_df['matches_write_set'] & \
                                       tx_master_df['matches_error'] & \
                                       tx_master_df['matches_status']

tx_master_df['has_reference_run'] = ~pandas.isnull(tx_master_df['tx_id_REF'])

print('Refining status matches...')
gc.collect()

def refine_commit_status(row):
    current = row['status']
    ref = row['status_REF']
    if current == 'success':
        if ref == 'success':
            return '0_MATCH_SUCCESS'
        else:  # ref == 'failed'
            return 'UNEXPECTED_FAILURE'
    else:  # current == 'failed'
        if ref == 'success':
            return 'UNEXPECTED_SUCCESS'
        else:  # ref == 'failed'
            return '0_MATCH_FAILURE'


def refine_endorsement_error_match(row):
    current = row['ENDORSE_any_error']
    ref = row['ENDORSE_any_error_REF']

    if current:
        return 'TP' if ref else 'FP'

    return 'FN' if ref else 'TN'


def is_null_or_empty(string):
    return pandas.isna(string) or (string == '')


def refine_set_match(row, col):
    current = row[col]
    ref = row['{0}_REF'.format(col)]

    if is_null_or_empty(current) and is_null_or_empty(ref):
        return '0_MATCH_EMPTY'

    if current == ref:
        return '0_MATCH_ALL'

    return 'MISMATCH'


def refine_write_set_match(row):
    return refine_set_match(row, 'writes')


def refine_read_set_match(row):
    return refine_set_match(row, 'reads')
print("passei1")

try:

 tx_master_df['TX_commit_match_status_refined'] = tx_master_df.apply(refine_commit_status, axis=1)
 tx_master_df['TX_commit_match_read_set_refined'] = tx_master_df.apply(refine_read_set_match, axis=1)
 tx_master_df['TX_commit_match_write_set_refined'] = tx_master_df.apply(refine_write_set_match, axis=1)
 tx_master_df['TX_commit_match_endorse_error_refined'] = tx_master_df.apply(refine_endorsement_error_match, axis=1)
except Exception as e:
 print(e)
print("passei1.1")
tx_master_df['TX_commit_match_endorse_error'] = (tx_master_df['TX_commit_match_endorse_error_refined'] == 'TP') | \
                                                (tx_master_df['TX_commit_match_endorse_error_refined'] == 'TN')

tx_master_df['TX_client_view_consistent'] = tx_master_df['matches_return_value'] & tx_master_df['matches_status'] & \
                                            tx_master_df['TX_commit_match_endorse_error']
tx_master_df['TX_hidden_side_effect'] = tx_master_df['TX_client_view_consistent'] & ~tx_master_df['matches_write_set']

tx_master_df['TX_ref_writeset_empty'] = tx_master_df['write_set_empty_REF']

print("pssei2")
def get_family_base(row):
    class_name = row['contract_classname']
    if class_name.endswith('Protected'):
        return class_name[:class_name.rfind('Protected')]
    if class_name.endswith('Stripped'):
        return class_name[:class_name.rfind('Stripped')]
    return class_name


def get_protection_type(row):
    class_name = row['contract_classname']
    if class_name.endswith('Protected'):
        return 'protected'
    if class_name.endswith('Stripped'):
        return 'stripped'
    return 'baseline'

try:
  tx_master_df['ID_contract_family_base'] = tx_master_df.apply(get_family_base, axis=1)
  tx_master_df['ID_protection_type'] = tx_master_df.apply(get_protection_type, axis=1)
except Exception as e:
 # print(tx_master_df['ID_contract_family_base'])
  print("error: " + str(e))

# Error type detection
def is_error(row, error_string):
    org1_error = str(row['proposal_response_error_peer0.org1.example.com'])
    org2_error = str(row['proposal_response_error_peer0.org2.example.com'])
    return org1_error == error_string or org2_error == error_string


def is_fabric_timeout_error(row):
    return is_error(row, 'Fabric container timeout')


def is_evm_timeout_error(row):
    return is_error(row, 'insufficient gas')


def is_assert_error(row):
    return is_error(row, 'assert-induced abort')


def is_require_error(row):
    return is_error(row, 'require-induced revert')


def is_balance_error(row):
    return is_error(row, 'insufficient balance')


def is_modify_nonexistent_account_error(row):
    return is_error(row, 'attempted to modify non-existent account')


def is_create_account_permission_error(row):
    return is_error(row, 'create account permission error')


tx_master_df['ERROR_is_fabric_timeout'] = tx_master_df.apply(is_fabric_timeout_error, axis=1)
tx_master_df['ERROR_is_evm_timeout'] = tx_master_df.apply(is_evm_timeout_error, axis=1)
tx_master_df['ERROR_is_assert'] = tx_master_df.apply(is_assert_error, axis=1)
tx_master_df['ERROR_is_require'] = tx_master_df.apply(is_require_error, axis=1)
tx_master_df['ERROR_is_balance'] = tx_master_df.apply(is_balance_error, axis=1)
tx_master_df['ERROR_is_modify_nonexistent_account'] = tx_master_df.apply(is_modify_nonexistent_account_error, axis=1)
tx_master_df['ERROR_is_create_account_permission'] = tx_master_df.apply(is_create_account_permission_error, axis=1)

# high-level categories
tx_master_df['ERROR_is_timeout'] = tx_master_df['ERROR_is_fabric_timeout'] | tx_master_df['ERROR_is_evm_timeout']
tx_master_df['ERROR_is_fabric_level'] = tx_master_df['ERROR_is_fabric_timeout']
tx_master_df['ERROR_is_evm_level'] = tx_master_df['ERROR_is_evm_timeout'] | tx_master_df['ERROR_is_balance'] | \
                                     tx_master_df['ERROR_is_modify_nonexistent_account'] | \
                                     tx_master_df['ERROR_is_create_account_permission']
tx_master_df['ERROR_is_platform_level'] = tx_master_df['ERROR_is_fabric_level'] | tx_master_df['ERROR_is_evm_level']
tx_master_df['ERROR_is_application_level'] = tx_master_df['ERROR_is_assert'] | tx_master_df['ERROR_is_require']

print("passei3")
#######################
# FORMAL VERIFICATION #
#######################


def refine_formal_result(row):
    faulty = row['faulty_contract']
    said_good = row['FormalResult']

    # said_good could be boolean or string, depending on whether there's UNKNOWN value

    if not faulty:
        if said_good == 'TRUE' or said_good:
            return 'TP'
        if said_good == 'FALSE' or not said_good:
            return 'FN'
        if said_good == 'UNKNOWN':
            return 'UNKNOWN'

    if faulty:
        if said_good == 'TRUE' or said_good:
            return 'FP'
        if said_good == 'FALSE' or not said_good:
            return 'TN'
        if said_good == 'UNKNOWN':
            return 'UNKNOWN'

    print(f'Formal classification error: faulty: {faulty}, result: {said_good}')
    sys.exit(1)


if args.formal != '':
    formal_search_pattern = '{0}/*.csv'.format(args.formal)

    formal_csvs = glob.glob(formal_search_pattern, recursive=False)
    formal_csvs.sort()

    if len(formal_csvs) == 0:
        print('''Search pattern '{0}' didn't match any formal verification files'''.format(formal_search_pattern))
    else:
        formal_dfs = []
        print(f'Reading {len(formal_csvs)} verification result CSVs...')
        for csv_file in formal_csvs:
            file_name = os.path.splitext(os.path.basename(csv_file))[0]
            df = pandas.read_csv(csv_file, header=0, low_memory=False, delimiter=',')
            formal_dfs.append(df)

        print('Concatenating formal verification data frames...')
        formal_df = pandas.concat(formal_dfs, ignore_index=False)

        print('Merging formal verification results...')
        tx_master_df = pandas.merge(tx_master_df, formal_df, how='left', left_on=['contract_name'],
                                    right_on=['ID_contract_filename'])

        print('Refining formal verification results...')
        tx_master_df['FORMAL_result_classification'] = tx_master_df.apply(refine_formal_result, axis=1)
        tx_master_df['FORMAL_result_correct'] = tx_master_df.apply(
            lambda row: (row['FORMAL_result_classification'] == 'TP') or
                        (row['FORMAL_result_classification'] == 'TN'), axis=1)
else:
    print('Directory for formal verification CSVs not set')

###################
# POST-PROCESSING #
###################
gc.collect()
debug_csv_file = '{0}/MERGED_DEBUG.csv'.format(output_dir)
print('Saving {0}'.format(debug_csv_file))
tx_master_df.to_csv(debug_csv_file, index=False, sep=',')

print('Cleaning up before saving...')
ref_columns = [col for col in tx_master_df.columns if col.endswith('_REF')]
tx_master_df.drop(columns=ref_columns, inplace=True, errors='ignore')
tx_master_df.sort_values(by=['time_create'], inplace=True)

tx_master_df.rename(mapper=col_rename, axis='columns', inplace=True)

keep_columns = [col for col in col_order if col in tx_master_df.columns]
tx_master_df = tx_master_df[keep_columns]

merged_csv_file = '{0}/MERGED.csv'.format(output_dir)
print('Saving {0}'.format(merged_csv_file))
tx_master_df.to_csv(merged_csv_file, index=False, sep=',')
