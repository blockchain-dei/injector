import os
import pandas
import argparse
import yaml
import sys

#################
# CLI INTERFACE #
#################

parser = argparse.ArgumentParser(description='Aggregates a transaction data CSV')

parser.add_argument('input', help='the path of the TX CSV to aggregate')
parser.add_argument('-l', '--delimiter', metavar='char', default=',', help='delimiter character of the CSVs')

args = parser.parse_args()

############
# READ CSV #
############

print(f'Reading CSV: {args.input}')
df = pandas.read_csv(args.input, low_memory=False, delimiter=args.delimiter)

########################
# DATA INTEGRITY ERROR #
########################

print(f'Calculating data integrity errors...')

ws_mismatch = ~df['TX_commit_match_write_set']
tx_success = df['COMMIT_anypeer_failure'] == 'success'
df['TX_data_integrity_error'] = ws_mismatch & tx_success

#####################
# RELIABILITY ERROR #
#####################
print(f'Calculating reliability errors...')

df['TX_reliability_error'] = ~df['TX_client_view_consistent']

#######################
# ACCESSIBILITY ERROR #
#######################
print(f'Calculating accessibility errors...')

df['TX_accessibility_error'] = df['TX_ref_success'] & (df['COMMIT_anypeer_failure'] == 'failed')
df['FORMAL_detected'] = ~df['FORMAL_result']

############################
# GROUPING AND AGGREGATION #
############################

print(f'Grouping and aggregation...')


def load_yaml(file):
    with open(file, 'r') as stream:
        try:
            return yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(f'Couldn\'t load YAML file {file}')
            print(exc)
            sys.exit(1)


aggreg_list = load_yaml('./configs/aggregate.yaml')


def any_first(result_df, group_df, index, source, target):
    if source not in group_df.columns:
        print(f'Source column "{source}" does not exist in data frame group')
        return
    result_df[target] = group_df[source].iloc[0]
    index.append(target)


def bool_all(result_df, group_df, index, source, target):
    if source not in group_df.columns:
        print(f'Source column "{source}" does not exist in data frame group')
        return
    result_df[target] = group_df[source].all()
    index.append(target)


def bool_any(result_df, group_df, index, source, target):
    if source not in group_df.columns:
        print(f'Source column "{source}" does not exist in data frame group')
        return
    result_df[target] = group_df[source].any()
    index.append(target)


def aggregate(group_df):
    index = []
    result_df = {}

    for entry in aggreg_list:
        method = entry['method']
        source = entry['source']
        target = entry['target']

        if method == 'first':
            any_first(result_df, group_df, index, source, target)
        elif method == 'all':
            bool_all(result_df, group_df, index, source, target)
        elif method == 'any':
            bool_any(result_df, group_df, index, source, target)
        else:
            print(f'Unknown aggregation "{method}" for variable "{source}"')
            sys.exit(1)

    return pandas.Series(result_df, index=index)


groups = df.groupby(by='ID_contract_filename').apply(aggregate).reset_index()


def derive_detectable(row):
    if row['FORMAL_detected']:
        return 'Verification'

    if (not row['TX_commit_match_error']) and row['ERROR_is_application_level']:
        return 'SelfCheck'

    return 'None'


groups['Detectable'] = groups.apply(derive_detectable, axis=1)

output_dir = os.path.dirname(args.input)
aggregated_csv_file = f'{output_dir}/AGGREGATED.csv'
print(f'Saving {aggregated_csv_file}')
groups.to_csv(aggregated_csv_file, index=False, sep=',')
