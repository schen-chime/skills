import copy
import csv
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from login_volume_report import (
    SIGNALS, COHORTS, COUNTS, START, append_login_volume_report,
    summarize_login_volume, volume_svg, login_volume_html_section, hex_summary_rows,
)

CUTOFF = datetime(2026, 10, 26, 15, tzinfo=timezone.utc)


def record(kind, payload):
    return {'RECORD_TYPE': kind, 'PAYLOAD': payload}


def fixture(cutoff=CUTOFF, campaign=(10, 8, 4), baseline=(20, 10, 1)):
    rows, groups = [], []
    start = cutoff - timedelta(hours=168)
    for cohort in COHORTS:
        total, evaluated, positive = campaign if cohort == 'campaign' else baseline
        for signal in SIGNALS:
            for index in range(168):
                hour = start + timedelta(hours=index)
                row = {'cohort': cohort, 'signal': signal, 'hour_start': hour.isoformat(), 'hour_end': (hour + timedelta(hours=1)).isoformat(),
                    'qualified_attempts': total if index == 0 else 0, 'evaluated_attempts': evaluated if index == 0 else 0,
                    'triggered_attempts': positive if index == 0 else 0, 'unknown_attempts': total - evaluated if index == 0 else 0}
                rows.append(record('COHORT_LOGIN_HOURLY', row))
            groups.append({'cohort': cohort, 'signal': signal, 'qualified_attempts': total,
                'evaluated_attempts': evaluated, 'triggered_attempts': positive, 'unknown_attempts': total - evaluated})
    meta = {'cutoff': cutoff.isoformat(), 'window_start': start.isoformat(), 'extraction_complete': True,
        'query_available': True, 'expected_hourly_rows': 1344, 'emitted_hourly_rows': 1344, 'group_metrics': groups,
        'qualified_login_grain': 'ACCOUNT_ACCESS_ATTEMPT_ID', 'maximum_callback_age_hours': 24,
        'timestamp_method': 'Latest exact-registration callback at or before login, max24h'}
    return [record('COHORT_LOGIN_COVERAGE', meta), *rows]


def metric(summary, cohort='campaign', signal=SIGNALS[0]):
    return next(row for row in summary['metrics'] if row['cohort'] == cohort and row['signal'] == signal)


class LoginVolumeTests(unittest.TestCase):
    def test_full_contract_counts_and_descriptive_notes(self):
        summary = summarize_login_volume(fixture(), CUTOFF)
        self.assertEqual(summary['status'], 'AVAILABLE')
        self.assertEqual(len(summary['hourly']), 168 * 4 * 2)
        self.assertEqual(metric(summary)['triggered_attempts'], 4)
        self.assertEqual(metric(summary)['evaluated_attempts'], 8)
        self.assertEqual(metric(summary)['unknown_attempts'], 2)
        self.assertEqual(len(summary['higher_than_baseline_notes']), 4)
        self.assertEqual(summary['higher_than_baseline_notes'][0]['campaign_coverage'], .8)
        self.assertIn('not a significance test', summary['higher_than_baseline_notes'][0]['description'])
        self.assertIn('overlap', summary['overlap'])
        self.assertIn('at or before', summary['method'])

    def test_nested_cli_and_serialized_payloads(self):
        data = fixture()
        wrapped = {'statements': [{'data': [{'record_type': row['RECORD_TYPE'], 'payload': json.dumps(row['PAYLOAD'])} for row in data]}]}
        self.assertEqual(summarize_login_volume(wrapped, CUTOFF)['status'], 'AVAILABLE')

    def test_unrelated_record_does_not_require_valid_payload(self):
        data = [record('EVENT', 'not JSON'), *fixture()]
        self.assertEqual(summarize_login_volume(data, CUTOFF)['status'], 'AVAILABLE')

    def test_no_metadata_never_imputes_zero(self):
        summary = summarize_login_volume(fixture()[1:], CUTOFF)
        self.assertEqual(summary['status'], 'UNAVAILABLE')
        self.assertTrue(all(row['triggered_attempts'] is None for row in summary['hourly']))
        self.assertEqual(summary['higher_than_baseline_notes'], [])
        self.assertIsNone(metric(summary)['triggered_attempts'])
        self.assertIsNone(metric(summary)['qualified_attempts'])

    def test_explicit_unavailability_hides_counts(self):
        data = fixture()
        data[0]['PAYLOAD']['query_available'] = False
        summary = summarize_login_volume(data, CUTOFF)
        self.assertEqual(summary['status'], 'UNAVAILABLE')
        self.assertIsNone(summary['hourly'][0]['qualified_attempts'])

    def test_missing_bucket_is_gap_even_if_extraction_complete(self):
        data = fixture()
        del data[1]
        data[0]['PAYLOAD'].pop('expected_hourly_rows')
        data[0]['PAYLOAD'].pop('emitted_hourly_rows')
        data[0]['PAYLOAD'].pop('group_metrics')
        summary = summarize_login_volume(data, CUTOFF)
        self.assertEqual(summary['status'], 'PARTIAL')
        self.assertIsNone(summary['hourly'][0]['triggered_attempts'])
        self.assertEqual(summary['hourly'][1]['triggered_attempts'], 0)
        self.assertEqual(metric(summary)['covered_hours'], 167)
        self.assertNotIn(SIGNALS[0], [row['signal'] for row in summary['higher_than_baseline_notes']])

    def test_empty_document_has_eight_full_unknown_series(self):
        summary = summarize_login_volume([], CUTOFF)
        self.assertEqual(len(summary['hourly']), 1344)
        self.assertEqual(len(summary['metrics']), 8)
        self.assertEqual(summary['status'], 'UNAVAILABLE')

    def test_metadata_truncation_rejected(self):
        data = fixture()
        del data[-1]
        with self.assertRaisesRegex(ValueError, 'hourly_rows does not reconcile'):
            summarize_login_volume(data, CUTOFF)

    def test_top_level_qualified_total_must_reconcile(self):
        data = fixture()
        data[0]['PAYLOAD']['qualified_attempts'] = 31
        with self.assertRaisesRegex(ValueError, 'qualified_attempts total does not reconcile'):
            summarize_login_volume(data, CUTOFF)
        data[0]['PAYLOAD']['qualified_attempts'] = 30
        self.assertEqual(summarize_login_volume(data, CUTOFF)['status'], 'AVAILABLE')

    def test_metadata_group_count_mismatch_rejected(self):
        data = fixture()
        data[0]['PAYLOAD']['group_metrics'][0]['triggered_attempts'] = 3
        with self.assertRaisesRegex(ValueError, 'does not reconcile'):
            summarize_login_volume(data, CUTOFF)

    def test_exact_duplicate_is_deduped_but_conflict_rejected(self):
        data = fixture()
        data.append(copy.deepcopy(data[1]))
        summary = summarize_login_volume(data, CUTOFF)
        self.assertEqual(summary['deduplicated_exact_rows'], 1)
        data[-1]['PAYLOAD']['triggered_attempts'] = 3
        with self.assertRaisesRegex(ValueError, 'Conflicting duplicate'):
            summarize_login_volume(data, CUTOFF)

    def test_invalid_counts_rejected(self):
        for field, value in [('triggered_attempts', 9), ('evaluated_attempts', 11), ('unknown_attempts', 9), ('qualified_attempts', -1), ('qualified_attempts', True), ('triggered_attempts', .5), ('evaluated_attempts', None)]:
            with self.subTest(field=field, value=value):
                data = fixture()
                data[1]['PAYLOAD'][field] = value
                with self.assertRaises(ValueError):
                    summarize_login_volume(data, CUTOFF)

    def test_denominator_must_agree_across_four_signals(self):
        data = fixture()
        data[0]['PAYLOAD'].pop('group_metrics')
        row = data[169]['PAYLOAD']
        row['qualified_attempts'] += 1
        row['unknown_attempts'] += 1
        with self.assertRaisesRegex(ValueError, 'denominators disagree'):
            summarize_login_volume(data, CUTOFF)

    def test_timestamp_window_boundaries_and_alignment(self):
        for hour in [CUTOFF, CUTOFF - timedelta(hours=169), CUTOFF - timedelta(hours=167, minutes=30)]:
            with self.subTest(hour=hour):
                data = fixture()
                data[1]['PAYLOAD']['hour_start'] = hour.isoformat()
                with self.assertRaisesRegex(ValueError, '168-hour window'):
                    summarize_login_volume(data, CUTOFF)

    def test_cutoff_metadata_and_hour_end_validated(self):
        data = fixture()
        data[0]['PAYLOAD']['cutoff'] = (CUTOFF + timedelta(hours=1)).isoformat()
        with self.assertRaisesRegex(ValueError, 'cutoff differs'):
            summarize_login_volume(data, CUTOFF)
        data = fixture()
        data[1]['PAYLOAD']['hour_end'] = CUTOFF.isoformat()
        with self.assertRaisesRegex(ValueError, 'hour_end'):
            summarize_login_volume(data, CUTOFF)
        half_hour_cutoff = CUTOFF + timedelta(minutes=30)
        shifted = summarize_login_volume(fixture(half_hour_cutoff), half_hour_cutoff)
        self.assertEqual(shifted['status'], 'AVAILABLE')
        self.assertEqual(shifted['hourly'][0]['hour_start'], '2026-10-19T15:30:00Z')

    def test_dst_repeated_hour_remains_distinct_and_offset_labeled(self):
        cutoff = datetime(2026, 11, 2, 6, tzinfo=timezone.utc)
        summary = summarize_login_volume(fixture(cutoff), cutoff)
        local = [r['hour_local'] for r in summary['hourly'][:168]]
        self.assertIn('2026-11-01T01:00:00-05:00', local)
        self.assertIn('2026-11-01T01:00:00-06:00', local)
        self.assertEqual(len(set(r['hour_start'] for r in summary['hourly'][:168])), 168)

    def test_no_false_baseline_note_for_equal_or_lower_rates(self):
        summary = summarize_login_volume(fixture(campaign=(10, 10, 1), baseline=(20, 10, 1)), CUTOFF)
        self.assertEqual(summary['higher_than_baseline_notes'], [])
        summary = summarize_login_volume(fixture(campaign=(10, 10, 0), baseline=(20, 10, 1)), CUTOFF)
        self.assertEqual(summary['higher_than_baseline_notes'], [])

    def test_no_baseline_note_without_evaluated_denominator(self):
        summary = summarize_login_volume(fixture(campaign=(10, 0, 0), baseline=(20, 10, 1)), CUTOFF)
        self.assertEqual(summary['higher_than_baseline_notes'], [])
        self.assertIsNone(metric(summary)['trigger_rate'])

    def test_four_graphs_only_campaign_volume_with_168_bars(self):
        summary = summarize_login_volume(fixture(), CUTOFF)
        section = login_volume_html_section(summary)
        self.assertEqual(section.count('<svg '), 4)
        self.assertEqual(section.count('class="pi-hour covered"'), 168 * 4)
        chart = volume_svg(summary, SIGNALS[0])
        self.assertIn('data-volume="4"', chart)
        self.assertNotIn('data-volume="1"', chart)  # baseline is not plotted
        self.assertIn('qualified total: 10', chart)

    def test_idempotent_injection_precedes_secondary_device_diagnostic(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            (path / 'report.html').write_text('<html><main><!-- HK_PI_COHORT_EXTENSION_START --><section>devices</section></main></html>')
            (path / 'summary.json').write_text(json.dumps({'status': 'OK', 'core': 123}))
            append_login_volume_report(path, fixture(), CUTOFF)
            append_login_volume_report(path, fixture(), CUTOFF, timezone='America/Chicago')
            text = (path / 'report.html').read_text()
            self.assertEqual(text.count(START), 1)
            self.assertEqual(text.count('<svg '), 4)
            self.assertLess(text.index(START), text.index('<!-- HK_PI_COHORT_EXTENSION_START -->'))
            with (path / 'login_pi_hourly.csv').open() as handle:
                csvrows = list(csv.DictReader(handle))
            self.assertEqual(len(csvrows), 1344)
            self.assertEqual(csvrows[1]['triggered_attempts'], '0')
            self.assertEqual(json.loads((path / 'summary.json').read_text())['core'], 123)

    def test_unavailable_csv_has_blank_counts_and_main_partial(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            (path / 'summary.json').write_text('{"status":"OK"}')
            append_login_volume_report(path, [], CUTOFF)
            with (path / 'login_pi_hourly.csv').open() as handle:
                row = next(csv.DictReader(handle))
            self.assertEqual(row['triggered_attempts'], '')
            self.assertEqual(json.loads((path / 'summary.json').read_text())['status'], 'PARTIAL')

    def test_hex_eight_row_contract_preserves_full_arrays_and_nulls(self):
        rows = hex_summary_rows(summarize_login_volume(fixture(), CUTOFF))
        self.assertEqual(len(rows), 8)
        row = next(r for r in rows if r['cohort'] == 'campaign' and r['signal'] == SIGNALS[0])
        arrays = json.loads(row['hourly_json'])
        self.assertEqual(set(arrays), {'triggered', 'qualified', 'evaluated', 'unknown'})
        self.assertTrue(all(len(values) == 168 for values in arrays.values()))
        self.assertEqual(arrays['triggered'][0], 4)
        self.assertTrue(row['higher_than_baseline'])
        self.assertEqual(row['cutoff_utc'], '2026-10-26T15:00:00Z')
        self.assertIn('maximum_callback_age_hours', row['source_method_json'])
        unavailable = hex_summary_rows(summarize_login_volume([], CUTOFF))
        self.assertIsNone(json.loads(unavailable[0]['hourly_json'])['triggered'][0])
        self.assertFalse(unavailable[0]['higher_than_baseline'])

    def test_html_escapes_provenance(self):
        data = fixture()
        data[0]['PAYLOAD']['timestamp_method'] = '<script>alert(1)</script>'
        self.assertNotIn('<script>', login_volume_html_section(summarize_login_volume(data, CUTOFF)))


if __name__ == '__main__':
    unittest.main()
