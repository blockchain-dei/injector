import pandas
import argparse
import os

#################
# CLI INTERFACE #
#################

parser = argparse.ArgumentParser(description='Derives confusion matrices from an aggregated CSV')

parser.add_argument('input', help='the path of the aggregated CSV')
parser.add_argument('-l', '--delimiter', metavar='char', default=',', help='delimiter character of the CSVs')

args = parser.parse_args()

############
# READ CSV #
############

print(f'Reading aggregated CSV: {args.input}')
df = pandas.read_csv(args.input, low_memory=False, delimiter=args.delimiter)

print(f'Calculating confusion matrix')

# matrix source DF
msd = df[['ID_contract_filename', 'ID_protection_type', 'ID_duplicate_contract', 'ID_faulty_contract', 'FORMAL_result',
          'TX_data_integrity_error', 'TX_reliability_error', 'TX_accessibility_error',
          'TX_hidden_side_effect', 'ERROR_is_timeout', 'TX_execution_fullmatch']]

msd = msd[~msd['ID_duplicate_contract']]

matrix_df = pandas.DataFrame(columns=['METRIC', 'SUM_TN', 'SUM_FP', 'BASELINE_TN', 'BASELINE_FP',
                                      'STRIPPED_TN', 'STRIPPED_FP', 'PROTECTED_TN', 'PROTECTED_FP'])

# conditions
faulty = msd['ID_faulty_contract']
verif_says_correct = msd['FORMAL_result']

TN = faulty & ~verif_says_correct
FP = faulty & verif_says_correct

baseline = msd['ID_protection_type'] == 'baseline'
stripped = msd['ID_protection_type'] == 'stripped'
protected = msd['ID_protection_type'] == 'protected'

data_integrity_error = msd['TX_data_integrity_error']
reliability_error = msd['TX_reliability_error']
accessibility_error = msd['TX_accessibility_error']
hidden_side_effect = msd['TX_hidden_side_effect']
timeout = msd['ERROR_is_timeout']
full_match = msd['TX_execution_fullmatch']


def count_metric(metric_name, mask):
    global matrix_df
    matrix_df = matrix_df.append({
        'METRIC': metric_name,
        'SUM_TN': len(msd[TN & mask]),
        'SUM_FP': len(msd[FP & mask]),
        'BASELINE_TN': len(msd[TN & baseline & mask]),
        'BASELINE_FP': len(msd[FP & baseline & mask]),
        'STRIPPED_TN': len(msd[TN & stripped & mask]),
        'STRIPPED_FP': len(msd[FP & stripped & mask]),
        'PROTECTED_TN': len(msd[TN & protected & mask]),
        'PROTECTED_FP': len(msd[FP & protected & mask])
    }, ignore_index=True)


count_metric('data_integrity_holds', ~data_integrity_error)
count_metric('data_integrity_violated', data_integrity_error)
count_metric('reliability_holds', ~reliability_error)
count_metric('reliability_violated', reliability_error)
count_metric('accessibility_holds', ~accessibility_error)
count_metric('accessibility_violated', accessibility_error)
count_metric('no_hidden_side_effect_holds', ~hidden_side_effect)
count_metric('no_hidden_side_effect_violated', hidden_side_effect)
count_metric('no_timeout_holds', ~timeout)
count_metric('no_timeout_violated', timeout)
count_metric('full_match_holds', full_match)
count_metric('full_match_violated', ~full_match)

output_dir = os.path.dirname(args.input)
matrix_csv_file = f'{output_dir}/MATRIX.csv'
print(f'Saving {matrix_csv_file}')
matrix_df.to_csv(matrix_csv_file, index=False, sep=',')

print(f'Calculating relative confusion matrix')
all_count = len(msd[faulty])
baseline_count = len(msd[faulty & baseline])
stripped_count = len(msd[faulty & stripped])
protected_count = len(msd[faulty & protected])

matrix_df['SUM_TN'] /= all_count
matrix_df['SUM_FP'] /= all_count
matrix_df['BASELINE_TN'] /= baseline_count
matrix_df['BASELINE_FP'] /= baseline_count
matrix_df['STRIPPED_TN'] /= stripped_count
matrix_df['STRIPPED_FP'] /= stripped_count
matrix_df['PROTECTED_TN'] /= protected_count
matrix_df['PROTECTED_FP'] /= protected_count

matrix_csv_file = f'{output_dir}/MATRIX_PERCENTAGE.csv'
print(f'Saving {matrix_csv_file}')
matrix_df.to_csv(matrix_csv_file, index=False, sep=',')
