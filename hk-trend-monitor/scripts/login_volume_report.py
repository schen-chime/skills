#!/usr/bin/env python3
"""Offline qualified-login Play Integrity volume report.

Consumes only COHORT_LOGIN_HOURLY and COHORT_LOGIN_COVERAGE Snow CLI rows.
The four graphs count campaign login attempts, never device prevalence. Missing
extraction/buckets remain unknown; a zero requires a covered source bucket.
"""
import argparse
import csv
import html
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

UTC = timezone.utc
SIGNALS = ('unknown_controlling', 'known_controlling', 'known_only_controlling', 'any_controlling')
COHORTS = ('campaign', 'baseline')
LABELS = {
    'unknown_controlling': 'UNKNOWN_CONTROLLING',
    'known_controlling': 'KNOWN_CONTROLLING',
    'known_only_controlling': 'KNOWN_CONTROLLING only',
    'any_controlling': 'Any controlling signal',
}
COUNTS = ('qualified_attempts', 'evaluated_attempts', 'triggered_attempts', 'unknown_attempts')
START = '<!-- HK_PI_LOGIN_VOLUME_START -->'
END = '<!-- HK_PI_LOGIN_VOLUME_END -->'
METHOD = ('Each bar counts distinct qualified Android login attempts by campaign users, '
          'using the latest valid callback bound to the same registration at or before that login, no older than 24 hours. '
          'Callbacks after an attempt cannot qualify it. Repeated logins count as separate attempts; callbacks do not.')
OVERLAP = ('The four signals overlap: KNOWN and UNKNOWN may coexist; known-only excludes UNKNOWN; any controlling is their union. '
           'Do not add the four graph totals together.')
MISSING = ('Missing or unusable Play Integrity telemetry remains unknown. A bar of zero means a covered hour had no triggered attempts; '
           'a gray gap means extraction was unavailable or that hourly record was missing.')


def _time(value, field='timestamp'):
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        try:
            result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError as exc:
            raise ValueError(f'Invalid {field}: {value!r}') from exc
    else:
        raise ValueError(f'{field} must be an ISO timestamp')
    return (result.replace(tzinfo=UTC) if result.tzinfo is None else result).astimezone(UTC)


def _iso(value):
    return value.astimezone(UTC).isoformat().replace('+00:00', 'Z')


def _integer(value, field):
    if isinstance(value, bool) or value is None:
        raise ValueError(f'{field} must be a nonnegative integer')
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f'{field} must be a nonnegative integer') from exc
    if result < 0 or (not isinstance(value, int) and str(result) != str(value)):
        raise ValueError(f'{field} must be a nonnegative integer')
    return result


def _true(value):
    return value is True or value == 1 or (isinstance(value, str) and value.lower() == 'true')


def records_from_json(document):
    """Accept nested CLI result envelopes and serialized payload objects."""
    if isinstance(document, list):
        for item in document:
            yield from records_from_json(item)
    elif isinstance(document, dict):
        row = {str(k).lower(): v for k, v in document.items()}
        if 'record_type' in row:
            kind = str(row['record_type']).upper()
            if kind not in ('COHORT_LOGIN_HOURLY', 'COHORT_LOGIN_COVERAGE'):
                return
            payload = row.get('payload')
            if isinstance(payload, str):
                payload = json.loads(payload)
            if not isinstance(payload, dict):
                raise ValueError(f'{kind} PAYLOAD must be an object')
            yield kind, {str(k).lower(): v for k, v in payload.items()}
        else:
            for value in document.values():
                if isinstance(value, (list, dict)):
                    yield from records_from_json(value)


def _validate_counts(row, context):
    values = {field: _integer(row.get(field), field) for field in COUNTS}
    total, evaluated, positive, unknown = (values[k] for k in COUNTS[:4])
    if not positive <= evaluated <= total or unknown != total - evaluated:
        raise ValueError(f'{context}: triggered <= evaluated <= qualified and unknown = qualified - evaluated required')
    return values


def _metadata(document, cutoff, window_start, warnings):
    rows = [payload for kind, payload in records_from_json(document) if kind == 'COHORT_LOGIN_COVERAGE']
    if not rows:
        warnings.append('COHORT_LOGIN_COVERAGE is absent; hourly extraction availability is unverified.')
    declarations = {c: [] for c in COHORTS}
    for row in rows:
        for key in ('cutoff', 'as_of_utc', 'cutoff_utc', 'snapshot_end_utc'):
            if row.get(key) is not None and _time(row[key], key) != cutoff:
                raise ValueError('Login source cutoff differs from requested cutoff')
        for key in ('window_start', 'window_start_utc', 'chart_start'):
            if row.get(key) is not None and _time(row[key], key) != window_start:
                raise ValueError('Login source window is not exactly seven days before cutoff')
        complete = _true(row.get('extraction_complete'))
        for key in ('query_available', 'cohort_query_available', 'available', 'coverage_complete'):
            if key in row and not _true(row[key]):
                complete = False
        if str(row.get('status', '')).upper() in ('UNAVAILABLE', 'PARTIAL', 'ERROR', 'FAILED'):
            complete = False
        cohorts = [str(row['cohort']).lower()] if 'cohort' in row else list(COHORTS)
        if any(c not in COHORTS for c in cohorts):
            raise ValueError('Login coverage cohort must be campaign or baseline')
        for cohort in cohorts:
            declarations[cohort].append(complete)
    coverage = {cohort: bool(values) and all(values) for cohort, values in declarations.items()}
    for cohort in COHORTS:
        if not coverage[cohort]:
            warnings.append(f'{cohort}: extraction unavailable or explicitly incomplete; source counts are not plotted.')
    return rows, coverage


def _reconcile(metadata, source_rows, metrics):
    """Fail on declared truncation/count mismatches, rather than publish low rates."""
    for row in metadata:
        if (not _true(row.get('extraction_complete'))
                or any(key in row and not _true(row[key]) for key in ('query_available', 'cohort_query_available', 'available', 'coverage_complete'))
                or str(row.get('status', '')).upper() in ('UNAVAILABLE', 'PARTIAL', 'ERROR', 'FAILED')):
            continue
        selected = [r for r in source_rows if row.get('cohort') is None or r['cohort'] == str(row['cohort']).lower()]
        for key in ('emitted_hourly_rows', 'expected_hourly_rows'):
            if key in row and _integer(row[key], key) != len(selected):
                raise ValueError(f'Login coverage {key} does not reconcile with hourly rows')
        if 'qualified_attempts' in row:
            declared_total = _integer(row['qualified_attempts'], 'qualified_attempts')
            observed_total = sum(m['qualified_attempts'] for m in metrics if m['signal'] == SIGNALS[0] and (row.get('cohort') is None or m['cohort'] == str(row['cohort']).lower()))
            if declared_total != observed_total:
                raise ValueError('Login coverage qualified_attempts total does not reconcile')
        for declared in row.get('group_metrics', []):
            target = next((m for m in metrics if m['cohort'] == str(declared.get('cohort', '')).lower() and m['signal'] == str(declared.get('signal', '')).lower()), None)
            if target is None:
                raise ValueError('Login coverage group_metrics requires known cohort and signal')
            for field in COUNTS:
                if field in declared and _integer(declared[field], field) != target[field]:
                    raise ValueError(f'Login coverage {target["cohort"]}/{target["signal"]}/{field} does not reconcile')


def summarize_login_volume(document, as_of_utc, timezone_name='America/Chicago'):
    cutoff = _time(as_of_utc, 'as_of_utc')
    start = cutoff - timedelta(hours=168)
    local_tz = ZoneInfo(timezone_name)
    warnings = []
    metadata, coverage = _metadata(document, cutoff, start, warnings)
    indexed = {}
    duplicates = 0
    for kind, raw in records_from_json(document):
        if kind != 'COHORT_LOGIN_HOURLY':
            continue
        cohort, signal = str(raw.get('cohort', '')).lower(), str(raw.get('signal', '')).lower()
        if cohort not in COHORTS or signal not in SIGNALS:
            raise ValueError('Hourly row requires known cohort and signal')
        hour = _time(raw.get('hour_start'), 'hour_start')
        if not start <= hour < cutoff or (hour - start).total_seconds() % 3600:
            raise ValueError('Hourly row lies outside/aligned incorrectly with the 168-hour window')
        if raw.get('hour_end') is not None and _time(raw['hour_end'], 'hour_end') != min(hour + timedelta(hours=1), cutoff):
            raise ValueError('Hourly row hour_end must be one hour after hour_start')
        row = {'cohort': cohort, 'signal': signal, 'hour_start': _iso(hour), 'hour_end': _iso(hour + timedelta(hours=1)), **_validate_counts(raw, f'{cohort}/{signal}/{hour}')}
        key = cohort, signal, hour
        if key in indexed:
            if indexed[key] != row:
                raise ValueError('Conflicting duplicate login hourly record')
            duplicates += 1
        indexed[key] = row
    hourly = []
    for cohort in COHORTS:
        for signal in SIGNALS:
            for index in range(168):
                instant = start + timedelta(hours=index)
                source = indexed.get((cohort, signal, instant))
                available = coverage[cohort] and source is not None
                row = {'cohort': cohort, 'signal': signal, 'hour_start': _iso(instant), 'hour_end': _iso(instant + timedelta(hours=1)), 'hour_local': instant.astimezone(local_tz).isoformat(), 'source_available': available}
                row.update({field: source[field] if available else None for field in COUNTS})
                hourly.append(row)
    metrics = []
    for cohort in COHORTS:
        for signal in SIGNALS:
            rows = [r for r in hourly if r['cohort'] == cohort and r['signal'] == signal]
            covered = [r for r in rows if r['source_available']]
            count = {field: sum(r[field] for r in covered) if covered else None for field in COUNTS}
            metrics.append({'cohort': cohort, 'signal': signal, 'covered_hours': len(covered), 'expected_hours': 168,
                'status': 'AVAILABLE' if len(covered) == 168 else ('PARTIAL' if covered else 'UNAVAILABLE'), **count,
                'trigger_rate': count['triggered_attempts'] / count['evaluated_attempts'] if count['evaluated_attempts'] else None,
                'evaluation_coverage': count['evaluated_attempts'] / count['qualified_attempts'] if count['qualified_attempts'] else None})
    _reconcile(metadata, list(indexed.values()), metrics)
    for cohort in COHORTS:
        qualified_vectors = [[indexed[(cohort, signal, start + timedelta(hours=i))]['qualified_attempts'] if (cohort, signal, start + timedelta(hours=i)) in indexed else None for i in range(168)] for signal in SIGNALS]
        for vectors in (qualified_vectors,):
            for i in range(168):
                values = {vector[i] for vector in vectors if vector[i] is not None}
                if len(values) > 1:
                    raise ValueError('Qualified attempt denominators disagree across signals')
    missing = sum(not r['source_available'] for r in hourly)
    if missing:
        warnings.append(f'{missing} of 1,344 signal/cohort/hour buckets are unavailable; no zero was imputed.')
    notes = []
    for signal in SIGNALS:
        c, b = (next(m for m in metrics if m['cohort'] == cohort and m['signal'] == signal) for cohort in COHORTS)
        if c['status'] != 'AVAILABLE' or b['status'] != 'AVAILABLE':
            continue
        if c['trigger_rate'] is not None and b['trigger_rate'] is not None and c['trigger_rate'] > b['trigger_rate']:
            notes.append({'signal': signal, 'campaign_rate': c['trigger_rate'], 'baseline_rate': b['trigger_rate'],
                'campaign_triggered': c['triggered_attempts'], 'campaign_evaluated': c['evaluated_attempts'],
                'baseline_triggered': b['triggered_attempts'], 'baseline_evaluated': b['evaluated_attempts'],
                'campaign_coverage': c['evaluation_coverage'], 'baseline_coverage': b['evaluation_coverage'],
                'description': 'Observed campaign trigger rate is higher than the sampled baseline. This is descriptive, not a significance test; unequal telemetry coverage and repeated user/device attempts can affect the comparison.'})
    statuses = {m['status'] for m in metrics}
    status = 'AVAILABLE' if statuses == {'AVAILABLE'} else ('UNAVAILABLE' if statuses == {'UNAVAILABLE'} else 'PARTIAL')
    return {'status': status, 'as_of_utc': _iso(cutoff), 'window_start_utc': _iso(start), 'timezone': timezone_name,
        'method': METHOD, 'overlap': OVERLAP, 'missing_semantics': MISSING, 'hourly': hourly, 'metrics': metrics,
        'higher_than_baseline_notes': notes, 'coverage_metadata': metadata, 'deduplicated_exact_rows': duplicates,
        'warnings': warnings, 'graph_population': 'campaign', 'count_grain': 'qualified_login_attempt', 'expected_buckets': 1344}


def hex_summary_rows(summary):
    """Compact eight-row Hex app contract; keep every hourly array below 50-row cap.

    Each row contains one cohort/signal, four 168-element arrays packed into
    hourly_json, UTC bounds, whole-window counts/rates, coverage and provenance.
    Nulls remain JSON null, including unavailable hourly extraction. JavaScript
    should derive hourly instants from window_start_utc + i * 3,600,000.
    """
    output = []
    notes = {row['signal']: row for row in summary['higher_than_baseline_notes']}
    for cohort in COHORTS:
        for signal in SIGNALS:
            metric = next(r for r in summary['metrics'] if r['cohort'] == cohort and r['signal'] == signal)
            series = [r for r in summary['hourly'] if r['cohort'] == cohort and r['signal'] == signal]
            arrays = {name: [r[field] for r in series] for name, field in (
                ('triggered', 'triggered_attempts'), ('qualified', 'qualified_attempts'),
                ('evaluated', 'evaluated_attempts'), ('unknown', 'unknown_attempts'))}
            if len(series) != 168:
                raise ValueError('Hex summary requires exactly 168 hourly records per cohort/signal')
            output.append({**metric, 'label': LABELS[signal],
                'cutoff_utc': summary['as_of_utc'], 'window_start_utc': summary['window_start_utc'],
                'timezone': summary['timezone'], 'count_grain': summary['count_grain'],
                'hourly_json': json.dumps(arrays, separators=(',', ':'), allow_nan=False),
                'higher_than_baseline': cohort == 'campaign' and signal in notes,
                'comparison_note': notes[signal]['description'] if cohort == 'campaign' and signal in notes else '',
                'qualification_method': summary['method'], 'overlap_note': summary['overlap'],
                'missing_semantics': summary['missing_semantics'],
                'source_method_json': json.dumps(summary['coverage_metadata'], separators=(',', ':'), ensure_ascii=False, allow_nan=False),
                'warnings_json': json.dumps(summary['warnings'], separators=(',', ':'), ensure_ascii=False),
            })
    return output


def _number(value):
    return 'unavailable' if value is None else f'{value:,}'


def _pct(value):
    return 'unknown' if value is None else f'{value:.2%}'


def volume_svg(summary, signal):
    rows = [r for r in summary['hourly'] if r['cohort'] == 'campaign' and r['signal'] == signal]
    width, height, left, top, bottom, step = 1250, 280, 48, 22, 218, 7
    peak = max([r['triggered_attempts'] for r in rows if r['triggered_attempts'] is not None] + [1])
    title = LABELS[signal] + ': qualified campaign login attempts triggering the signal by hour'
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="{html.escape(title)}" viewBox="0 0 {width} {height}"><title>{html.escape(title)}</title>']
    for index in range(5):
        y = bottom - (bottom - top) * index / 4
        parts.append(f'<line x1="{left}" y1="{y}" x2="1225" y2="{y}" stroke="#e0e7ef"/><text x="42" y="{y + 4}" text-anchor="end" font-size="11" fill="#50647c">{round(peak * index / 4)}</text>')
    for index, row in enumerate(rows):
        value = row['triggered_attempts']
        x = left + index * step
        tooltip = (f"{row['hour_local']} | triggered: {'unavailable' if value is None else value}; "
            f"evaluated: {row['evaluated_attempts']}; unknown: {row['unknown_attempts']}; qualified total: {row['qualified_attempts']}")
        bar_height = 8 if value is None else (bottom - top) * value / peak
        # Zero has a 1px baseline tick; unavailable is a gray gap marker.
        bar_height = max(1, bar_height)
        parts.append(f'<rect class="pi-hour {"unknown" if value is None else "covered"}" data-hour="{index}" data-volume="{"null" if value is None else value}" x="{x}" y="{bottom - bar_height}" width="5.5" height="{bar_height}" fill="{"#b5bfcb" if value is None else "#14675e"}"><title>{html.escape(tooltip)}</title></rect>')
        if index % 24 == 0 or index == 167:
            label = row['hour_local'][5:16].replace('T', ' ') + row['hour_local'][-6:]
            anchor = 'end' if index == 167 else 'start'
            parts.append(f'<text x="{x}" y="239" font-size="10" text-anchor="{anchor}" fill="#50647c">{html.escape(label)}</text>')
    parts.append('<text x="48" y="268" font-size="11" fill="#50647c">Hourly triggered attempt volume · 168 elapsed hours · hover bars for evaluated, unknown and qualified counts</text></svg>')
    return ''.join(parts)


def login_volume_html_section(summary):
    esc = html.escape
    plots = []
    for signal in SIGNALS:
        metric = next(r for r in summary['metrics'] if r['cohort'] == 'campaign' and r['signal'] == signal)
        plots.append(f'<article><h3>{esc(LABELS[signal])}</h3><p>{_number(metric["triggered_attempts"])} triggered attempts / {_number(metric["evaluated_attempts"])} evaluated; {_number(metric["unknown_attempts"])} unknown; {_number(metric["qualified_attempts"])} qualified (covered-hour totals). Coverage: {metric["covered_hours"]}/168 hours.</p><div style="overflow:auto;min-width:0">{volume_svg(summary, signal)}</div></article>')
    notes = []
    for row in summary['higher_than_baseline_notes']:
        notes.append(f'<li><strong>{esc(LABELS[row["signal"]])}:</strong> campaign {row["campaign_triggered"]:,}/{row["campaign_evaluated"]:,} ({_pct(row["campaign_rate"])}) versus sampled baseline {row["baseline_triggered"]:,}/{row["baseline_evaluated"]:,} ({_pct(row["baseline_rate"])}). Evaluation coverage: {_pct(row["campaign_coverage"])} versus {_pct(row["baseline_coverage"])}. {esc(row["description"])}</li>')
    note_text = '<ul>' + ''.join(notes) + '</ul>' if notes else '<p>No fully covered signal comparison had a higher observed campaign rate, or comparison data was unavailable.</p>'
    warnings = '<ul>' + ''.join('<li>' + esc(w) + '</li>' for w in summary['warnings']) + '</ul>' if summary['warnings'] else ''
    return f'<section class="card" id="play-integrity-login-volume"><h2>Play Integrity: qualified campaign login volume <span class="badge">{esc(summary["status"])}</span></h2><p>Exclusive cutoff {esc(summary["as_of_utc"])}; window starts {esc(summary["window_start_utc"])}. Axis: {esc(summary["timezone"])}.</p><p>{esc(summary["method"])}</p><p>{esc(summary["overlap"])}</p>{"".join(plots)}<h3>Descriptive comparison notes</h3>{note_text}<p>{esc(summary["missing_semantics"])}</p>{warnings}<p><a href="login_pi_hourly.csv" download>Hourly attempt counts</a> · <a href="login_pi_summary.json" download>Counts and provenance</a></p><details><summary>Qualification, timestamp and baseline methods</summary><pre>{esc(json.dumps(summary["coverage_metadata"], indent=2, ensure_ascii=False))}</pre></details></section>'


def _inject(text, section):
    block = START + '\n' + section + '\n' + END
    if START in text and END in text:
        before, rest = text.split(START, 1)
        _, after = rest.split(END, 1)
        return before + block + after
    # Put attempt charts before the secondary cohort-device snapshot diagnostic.
    insertion = '<!-- HK_PI_COHORT_EXTENSION_START -->'
    if insertion in text:
        return text.replace(insertion, block + '\n' + insertion, 1)
    return text.replace('</main>', block + '\n</main>', 1) if '</main>' in text else text + '\n' + block


def append_login_volume_report(out_dir, document, as_of_utc, timezone='America/Chicago'):
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    summary = summarize_login_volume(document, as_of_utc, timezone)
    (directory / 'login_pi_summary.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False, allow_nan=False) + '\n', encoding='utf-8')
    with (directory / 'login_pi_hourly.csv').open('w', newline='', encoding='utf-8') as handle:
        fields = ('cohort', 'signal', 'hour_start', 'hour_end', 'hour_local', 'source_available', *COUNTS)
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(summary['hourly'])
    section = login_volume_html_section(summary)
    (directory / 'login_pi_report.html').write_text('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Play Integrity qualified login volume</title><style>body{font:15px/1.5 system-ui;background:#f4f7fb;color:#172b4d;margin:24px}.card{background:white;border:1px solid #dce5ee;border-radius:12px;padding:24px;max-width:1280px;margin:auto}svg{width:100%;min-width:1000px}pre{white-space:pre-wrap}article{margin:32px 0}.badge{font-size:13px;background:#e9eef7;padding:4px 9px;border-radius:5px}</style></head><body><main>' + section + '</main></body></html>', encoding='utf-8')
    main_html = directory / 'report.html'
    if main_html.exists():
        text = main_html.read_text(encoding='utf-8')
        if summary['status'] != 'AVAILABLE':
            for old_status in ('OK', 'ALERT'):
                text = text.replace(f'<h1>HK trend monitor <span class="badge">{old_status}</span>', '<h1>HK trend monitor <span class="badge">PARTIAL</span>', 1)
        main_html.write_text(_inject(text, section), encoding='utf-8')
    main_json = directory / 'summary.json'
    if main_json.exists():
        report = json.loads(main_json.read_text(encoding='utf-8'))
        report['login_pi_monitor'] = summary
        if summary['status'] != 'AVAILABLE':
            report['status'] = 'PARTIAL'
            report['warnings'] = sorted(set(report.get('warnings', []) + ['Play Integrity qualified-login extraction unavailable or partial; no missing buckets were zero-filled.']))
        main_json.write_text(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + '\n', encoding='utf-8')
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--as-of', required=True)
    parser.add_argument('--out-dir', type=Path, required=True)
    parser.add_argument('--timezone', default='America/Chicago')
    args = parser.parse_args(argv)
    summary = append_login_volume_report(args.out_dir, json.loads(args.input.read_text(encoding='utf-8')), args.as_of, args.timezone)
    print(json.dumps({'status': summary['status'], 'hourly_buckets': len(summary['hourly']), 'report': str(args.out_dir / 'login_pi_report.html')}))


if __name__ == '__main__':
    main()
