#!/usr/bin/env python3
"""Read-only, dependency-free CSV/JSON observability profiler for HolmesGPT."""
import argparse
import collections
import csv
import datetime as dt
import gzip
import io
import json
import math
import os
from pathlib import Path
import re
import statistics
import sys

DEFAULT_ROOT = "/data/observability"
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_FIELDS = 200
NUMERIC_SAMPLE_CAP = 3000
SENSITIVE = re.compile(r"(password|passwd|secret|token|api[_-]?key|authorization|cookie|credential|private[_-]?key)", re.I)
SENSITIVE_ASSIGNMENT = re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization|cookie|credential)\s*([=:])\s*[^,;\s}]+")
BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+")
TIME_NAMES = ("timestamp", "time", "@timestamp", "ts", "datetime", "date", "start_time", "starttime", "starttimeunixnano")
TRACE_ID_NAMES = ("trace_id", "traceid", "trace.id")
SPAN_ID_NAMES = ("span_id", "spanid", "span.id")
SERVICE_NAMES = ("service", "service_name", "service.name", "app", "application")
METRIC_NAMES = ("metric", "metric_name", "__name__", "name")
VALUE_NAMES = ("value", "metric_value", "sample", "sample_value")
DURATION_NAMES = ("duration_ms", "duration_us", "duration_ns", "duration", "elapsed_ms")


def safe_string(value, max_chars=88):
    if value is None:
        return None
    text = str(value).replace("\n", " ").replace("\r", " ").replace("\t", " ")
    text = SENSITIVE_ASSIGNMENT.sub(r"\1\2[REDACTED]", text)
    text = BEARER_TOKEN.sub("Bearer [REDACTED]", text)
    return text[:max_chars] + ("..." if len(text) > max_chars else "")


def field_safe(key):
    return not SENSITIVE.search(str(key))


def accessible_path(requested):
    roots = [Path(s).resolve() for s in os.getenv("HOLMES_OBS_DATA_DIR", DEFAULT_ROOT).split(os.pathsep) if s]
    if not roots:
        raise ValueError("HOLMES_OBS_DATA_DIR has no approved directories")
    p = Path(requested).expanduser()
    if not p.is_absolute():
        p = roots[0] / p
    p = p.resolve(strict=True)
    if not p.is_file() or not any(p.is_relative_to(root) for root in roots):
        raise ValueError("Input must be a regular file within HOLMES_OBS_DATA_DIR")
    if p.suffix.lower() not in {".json", ".csv", ".jsonl", ".ndjson", ".gz"}:
        raise ValueError("Allowed extensions: .json, .csv, .jsonl, .ndjson and .gz")
    return p


def open_text(path):
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8-sig", errors="replace", newline="")
    return open(path, "r", encoding="utf-8-sig", errors="replace", newline="")


def float_number(value):
    try:
        if isinstance(value, bool) or value is None:
            return None
        val = float(value)
        return val if math.isfinite(val) else None
    except (ValueError, TypeError, OverflowError):
        return None


def time_iso(value):
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\d+(?:\.\d+)?", value.strip())):
            n = float(value)
            if not math.isfinite(n) or abs(n) < 100000000:
                return None
            magnitude = abs(n)
            if magnitude >= 1e17:
                n /= 1e9  # nanoseconds
            elif magnitude >= 1e14:
                n /= 1e6  # microseconds
            elif magnitude >= 1e11:
                n /= 1e3  # milliseconds
            return dt.datetime.fromtimestamp(n, tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")
        d = dt.datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        if d.tzinfo is None:
            # Do not silently assume local timezone for naive datetimes.
            return d.isoformat() + " (timezone unknown)"
        return d.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError):
        return None


def column_like(columns, options):
    lookup = {str(c).strip().lower(): c for c in columns}
    for name in options:
        if name in lookup:
            return lookup[name]
    return None


def summary_numbers(values):
    nums = [v for v in values if v is not None and math.isfinite(v)]
    if not nums:
        return {"numeric_count": 0}
    nums.sort()
    n = len(nums)
    def pct(p):
        pos = (n - 1) * p
        low, high = int(pos), math.ceil(pos)
        return round(nums[low] + (nums[high] - nums[low]) * (pos - low), 5)
    return {"numeric_count": n, "min": round(nums[0], 5), "max": round(nums[-1], 5),
            "mean": round(statistics.fmean(nums), 5), "p50": pct(.5), "p95": pct(.95),
            "first_sampled": round(values[0], 5) if values[0] is not None else None,
            "last_sampled": round(values[-1], 5) if values[-1] is not None else None}


def bounded_counter(counter, count=8):
    return [{"name": safe_string(k), "count": n} for k, n in counter.most_common(count)]


def summarize_csv(path, limit):
    warnings = []
    with open_text(path) as handle:
        sample = handle.read(8192)
        if not sample.strip():
            raise ValueError("CSV is empty")
        if "\x00" in sample:
            raise ValueError("Input looks binary, not a text CSV")
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        handle.seek(0)
        reader = csv.DictReader(handle, dialect=dialect)
        columns = reader.fieldnames or []
        if len(columns) > MAX_FIELDS:
            raise ValueError("Too many CSV columns; maximum is 200")
        if len(columns) != len(set(columns)):
            warnings.append("Duplicate CSV column names; values can be overwritten by DictReader")
        time_col = column_like(columns, TIME_NAMES)
        trace_col = column_like(columns, TRACE_ID_NAMES)
        span_col = column_like(columns, SPAN_ID_NAMES)
        metric_col = column_like(columns, METRIC_NAMES)
        value_col = column_like(columns, VALUE_NAMES)
        service_col = column_like(columns, SERVICE_NAMES)
        duration_col = column_like(columns, DURATION_NAMES)
        number_stats = collections.defaultdict(list)
        numeric_seen = collections.Counter()
        numeric_stride = collections.defaultdict(lambda: 1)
        nonempty = collections.Counter()
        missing = collections.Counter()
        categories = collections.defaultdict(collections.Counter)
        times = []
        errors = 0
        operations = collections.Counter()
        trace_ids = set()
        slow_spans = []
        total = 0
        for row in reader:
            if total >= limit:
                warnings.append(f"Analysis capped at {limit} data rows; statistics cover only the first {limit}")
                break
            total += 1
            for col in columns:
                if not field_safe(col):
                    continue
                value = row.get(col)
                if value is None or not str(value).strip():
                    missing[col] += 1
                    continue
                nonempty[col] += 1
                n = float_number(value)
                if n is not None:
                    numeric_seen[col] += 1
                    if numeric_seen[col] % numeric_stride[col] == 0:
                        if len(number_stats[col]) >= NUMERIC_SAMPLE_CAP:
                            number_stats[col] = number_stats[col][::2]
                            numeric_stride[col] *= 2
                        number_stats[col].append(n)
            if time_col and (t := time_iso(row.get(time_col))):
                times.append(t)
            for col in (metric_col, service_col, column_like(columns, ("operation", "operation_name", "span_name"))):
                if col and field_safe(col):
                    categories[col][safe_string(row.get(col))] += 1
            if trace_col and row.get(trace_col):
                if len(trace_ids) < 10000:
                    trace_ids.add(str(row[trace_col]))
            if trace_col or span_col:
                op_col = column_like(columns, ("operation", "operation_name", "span_name", "name"))
                if op_col:
                    operations[safe_string(row.get(op_col))] += 1
                err_col = column_like(columns, ("error", "is_error", "status_code", "http_status_code"))
                ev = row.get(err_col, "") if err_col else ""
                if str(ev).lower() in ("true", "1", "error", "status_code_error") or (float_number(ev) is not None and err_col and "status" in err_col and float(ev) >= 500):
                    errors += 1
                if duration_col and duration_col != "duration":
                    raw = float_number(row.get(duration_col))
                    if raw is not None:
                        d = raw / 1e6 if duration_col.endswith("_ns") else raw / 1e3 if duration_col.endswith("_us") else raw
                        span = {"duration_ms": round(d, 3), "trace_id": safe_string(row.get(trace_col)), "span_id": safe_string(row.get(span_col)), "operation": safe_string(row.get(op_col)) if op_col else None}
                        slow_spans.append(span)
                        slow_spans.sort(key=lambda s: s["duration_ms"], reverse=True)
                        del slow_spans[5:]
        top_numeric = sorted(number_stats.items(), key=lambda p: len(p[1]), reverse=True)[:12]
        stats = {str(k): {**summary_numbers(vals), "numeric_values_seen": numeric_seen[k],
                          "sampled": numeric_seen[k] > len(vals)} for k, vals in top_numeric}
        result = {
            "kind": "trace_csv" if (trace_col and span_col) else "metrics_csv" if (metric_col or value_col or time_col) else "generic_csv",
            "rows_examined": total,
            "columns": [safe_string(c) if field_safe(c) else "[REDACTED COLUMN]" for c in columns],
            "missing_by_column": {str(k): int(missing[k]) for k in columns if field_safe(k) and missing[k] and k in columns},
            "numeric_columns": stats,
            "top_categories": {str(k): bounded_counter(v) for k, v in categories.items()},
            "time_window": {"earliest": min(times), "latest": max(times), "parsed_timestamps": len(times)} if times else None,
        }
        if trace_col and span_col:
            result["traces"] = {"unique_trace_ids_at_least": len(trace_ids), "unique_trace_id_count_capped": len(trace_ids) >= 10000,
                                "error_spans": errors, "slowest_spans": slow_spans, "top_operations": bounded_counter(operations)}
        if duration_col == "duration" and trace_col:
            warnings.append("Ambiguous duration column: unit not specified. Provide duration_ms, duration_us or duration_ns to compare spans")
        if metric_col and not value_col:
            warnings.append("Metric name identified without a dedicated value column; inspect numeric_columns")
        if not total:
            warnings.append("CSV has headers but no data rows")
        if any(numeric_seen[k] > len(vals) for k, vals in number_stats.items()):
            warnings.append("Numeric values were downsampled to at most 3000 per column; numerical statistics are approximate")
        warnings.append("Numeric statistics are descriptive only; time-series were not aligned, rates and units were not inferred")
        return result, warnings


def unwrap_attributes(raw):
    if isinstance(raw, dict):
        return raw
    attributes = {}
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        key = item.get("key")
        if key:
            val = item.get("value")
            if isinstance(val, dict):
                val = next(iter(val.values()), None)
            attributes[str(key)] = val
    return attributes


class TraceSummary:
    def __init__(self, limit):
        self.limit = limit
        self.spans = 0
        self.errors = 0
        self.durations = []
        self.times = []
        self.services = collections.Counter()
        self.operations = collections.Counter()
        self.trace_ids = set()
        self.slowest = []
        self.truncated = False

    def add(self, trace_id, span_id, service, operation, duration_ms, start, error):
        if self.spans >= self.limit:
            self.truncated = True
            return
        self.spans += 1
        if trace_id and len(self.trace_ids) < 10000:
            self.trace_ids.add(str(trace_id))
        if service:
            self.services[safe_string(service)] += 1
        if operation:
            self.operations[safe_string(operation)] += 1
        if error:
            self.errors += 1
        if (t := time_iso(start)):
            self.times.append(t)
        if duration_ms is not None and duration_ms >= 0:
            self.durations.append(duration_ms)
            self.slowest.append({"duration_ms": round(duration_ms, 3), "service": safe_string(service),
                                 "operation": safe_string(operation), "trace_id": safe_string(trace_id), "span_id": safe_string(span_id)})
            self.slowest.sort(key=lambda s: s["duration_ms"], reverse=True)
            del self.slowest[5:]

    def output(self):
        result = {"kind": "traces", "spans_examined": self.spans,
                  "unique_trace_ids_at_least": len(self.trace_ids),
                  "unique_trace_id_count_capped": len(self.trace_ids) >= 10000,
                  "error_spans": self.errors,
                  "duration_ms": summary_numbers(self.durations),
                  "slowest_spans": self.slowest,
                  "top_services": bounded_counter(self.services),
                  "top_operations": bounded_counter(self.operations),
                  "time_window": {"earliest": min(self.times), "latest": max(self.times)} if self.times else None}
        warnings = []
        if self.truncated:
            warnings.append(f"Only the first {self.limit} spans analyzed")
        warnings.append("Duration percentiles are span-level, not end-to-end trace latency; parent/child spans can overlap")
        return result, warnings


def looks_error(tags, status):
    attributes = unwrap_attributes(tags)
    code = status.get("code") if isinstance(status, dict) else status
    if str(code).upper() in {"2", "ERROR", "STATUS_CODE_ERROR"}:
        return True
    error = attributes.get("error")
    if error is True or str(error).lower() in {"true", "1"}:
        return True
    for k in ("http.status_code", "http.response.status_code"):
        v = float_number(attributes.get(k))
        if v is not None and v >= 500:
            return True
    return False


def read_traces(payload, limit):
    t = TraceSummary(limit)
    if isinstance(payload, dict) and "resourceSpans" in payload:
        for resource in payload.get("resourceSpans") or []:
            svc = unwrap_attributes((resource.get("resource") or {}).get("attributes")).get("service.name")
            for scope in (resource.get("scopeSpans") or resource.get("instrumentationLibrarySpans") or []):
                for span in scope.get("spans", []):
                    start = span.get("startTimeUnixNano")
                    end = span.get("endTimeUnixNano")
                    try:
                        # OTLP nanosecond timestamps are often ~1e18; subtraction as float loses precision.
                        duration = (int(end) - int(start)) / 1e6
                    except (TypeError, ValueError, OverflowError):
                        duration = None
                    t.add(span.get("traceId"), span.get("spanId"), svc, span.get("name"), duration, start,
                          looks_error(span.get("attributes"), span.get("status")))
    elif isinstance(payload, dict) and isinstance(payload.get("data"), list):
        # Jaeger trace search/export: {data:[{traceID, spans:[], processes:{...}}]}
        for trace in payload["data"]:
            if not isinstance(trace, dict):
                continue
            processes = trace.get("processes") or {}
            for span in trace.get("spans") or []:
                proc = processes.get(span.get("processID"), {})
                svc = proc.get("serviceName")
                t.add(span.get("traceID") or trace.get("traceID"), span.get("spanID"), svc,
                      span.get("operationName"), float_number(span.get("duration")) / 1000 if float_number(span.get("duration")) is not None else None,
                      span.get("startTime"), looks_error(span.get("tags"), None))
    elif isinstance(payload, list):
        # Zipkin V2 spans are commonly an array.
        for span in payload:
            if not isinstance(span, dict):
                continue
            svc = (span.get("localEndpoint") or {}).get("serviceName")
            t.add(span.get("traceId") or span.get("traceID"), span.get("id"), svc, span.get("name"),
                  float_number(span.get("duration")) / 1000 if float_number(span.get("duration")) is not None else None, span.get("timestamp"),
                  looks_error(span.get("tags"), None))
    return t.output()


def summarize_dashboard(payload):
    dashboard = payload.get("dashboard") if isinstance(payload.get("dashboard"), dict) else payload
    panels = []
    def collect(items):
        for panel in items or []:
            if not isinstance(panel, dict):
                continue
            panels.append(panel)
            if panel.get("panels"):
                collect(panel["panels"])
    collect(dashboard.get("panels"))
    queries = []
    for panel in panels:
        targets = []
        for target in panel.get("targets") or []:
            if not isinstance(target, dict) or target.get("hide"):
                continue
            expr = target.get("expr") or target.get("query") or target.get("rawSql") or target.get("target")
            if expr:
                targets.append({"ref_id": safe_string(target.get("refId")), "expression": safe_string(expr, 180)})
        if targets:
            queries.append({"panel_id": panel.get("id"), "title": safe_string(panel.get("title")),
                            "datasource": safe_string(panel.get("datasource"), 100), "targets": targets[:5]})
    variables = (dashboard.get("templating") or {}).get("list") or []
    result = {"kind": "grafana_dashboard_definition", "dashboard_title": safe_string(dashboard.get("title")),
              "uid": safe_string(dashboard.get("uid")), "panel_count_including_rows": len(panels),
              "panel_types": bounded_counter(collections.Counter(str(p.get("type", "unknown")) for p in panels)),
              "variable_names": [safe_string(x.get("name")) for x in variables[:20] if isinstance(x, dict)],
              "panel_queries_sample": queries[:12],
              "default_time": dashboard.get("time") if isinstance(dashboard.get("time"), dict) else None}
    return result, ["This is a dashboard definition, not live metric values or an incident snapshot. Do not infer runtime health from panel queries."]


def summarize_prometheus(payload, limit):
    data = payload.get("data") or {}
    results = data.get("result") or []
    names = collections.Counter()
    series_output = []
    times = []
    all_values = []
    count = 0
    truncated = False
    for idx, series in enumerate(results):
        if idx >= 1000:
            truncated = True
            break
        metric = series.get("metric") or {}
        metric_name = metric.get("__name__", "(unnamed)")
        names[metric_name] += 1
        points = series.get("values")
        if points is None:
            points = [series["value"]] if "value" in series else []
        local = []
        for point in points:
            if count >= limit:
                truncated = True
                break
            if isinstance(point, (list, tuple)) and len(point) >= 2:
                count += 1
                if (val := float_number(point[1])) is not None:
                    local.append(val)
                    all_values.append(val)
                if (stamp := time_iso(point[0])):
                    times.append(stamp)
        if idx < 8:
            labels = {str(k): safe_string(v) for k, v in metric.items() if k != "__name__" and field_safe(k)}
            series_output.append({"metric": safe_string(metric_name), "labels": dict(list(labels.items())[:10]),
                                  "samples_examined": len(local), "sample_values": summary_numbers(local)})
        if count >= limit:
            break
    output = {"kind": "prometheus_api_result", "result_type": data.get("resultType"),
              "series_total": len(results), "series_examined": sum(names.values()), "samples_examined": count,
              "metric_names": bounded_counter(names, 15), "observed_sample_values": summary_numbers(all_values),
              "sample_series": series_output,
              "time_window": {"earliest": min(times), "latest": max(times)} if times else None}
    warnings = ["Sample statistics mix series/labels. Do not interpret them as a time-aligned sum, a rate, or an alert verdict."]
    if truncated:
        warnings.append("Series/samples capped; summary does not cover the full export")
    return output, warnings



def summarize_otel_metrics(payload, limit):
    names = collections.Counter()
    series = []
    values = []
    times = []
    points_count = 0
    for resource in payload.get("resourceMetrics") or []:
        for scope in resource.get("scopeMetrics") or resource.get("instrumentationLibraryMetrics") or []:
            for metric in scope.get("metrics") or []:
                name = safe_string(metric.get("name"))
                names[name] += 1
                mtype = next((k for k in ("gauge", "sum", "histogram", "exponentialHistogram", "summary") if k in metric), None)
                data = metric.get(mtype) or {}
                samples = data.get("dataPoints") or []
                if len(series) < 12:
                    series.append({"name": name, "unit": safe_string(metric.get("unit")),
                                   "type": mtype, "data_points": len(samples),
                                   "is_monotonic": data.get("isMonotonic") if mtype == "sum" else None})
                for point in samples:
                    if points_count >= limit:
                        break
                    points_count += 1
                    v = float_number(point.get("asDouble", point.get("asInt", point.get("sum"))))
                    if v is not None:
                        values.append(v)
                    stamp = time_iso(point.get("timeUnixNano"))
                    if stamp:
                        times.append(stamp)
    return {"kind": "opentelemetry_metrics", "metric_names": bounded_counter(names, 20),
            "metric_descriptors": series, "data_points_examined": points_count,
            "numeric_point_values": summary_numbers(values),
            "time_window": {"earliest": min(times), "latest": max(times)} if times else None}, [
                "Histogram sum/count are not standalone sample values. No bucket percentiles calculated.",
                "Mixed metric values and units must not be compared or aggregated; inspect metric descriptors separately."]


def summarize_grafana_frames(payload, limit):
    result = payload.get("results") or {}
    frames = []
    series = []
    times = []
    count = 0
    for ref_id, item in result.items():
        for frame in (item.get("frames") or []) if isinstance(item, dict) else []:
            if count >= limit:
                break
            fields = (frame.get("schema") or {}).get("fields") or []
            values = (frame.get("data") or {}).get("values") or []
            frames.append({"ref_id": safe_string(ref_id), "field_count": len(fields), "row_count": len(values[0]) if values and isinstance(values[0], list) else 0})
            for idx, field in enumerate(fields):
                if idx >= len(values):
                    continue
                field_data = values[idx] if isinstance(values[idx], list) else []
                avail = max(0, limit - count)
                selected = field_data[:avail]
                if str(field.get("type", "")).lower() == "time":
                    times.extend(t for v in selected if (t := time_iso(v)))
                elif str(field.get("type", "")).lower() == "number" and len(series) < 14:
                    series.append({"ref_id": safe_string(ref_id), "field": safe_string(field.get("name")),
                                   "labels": {str(k): safe_string(v) for k, v in (field.get("labels") or {}).items() if field_safe(k)},
                                   "values": summary_numbers([float_number(v) for v in selected])})
            count += len(values[0]) if values and isinstance(values[0], list) else 0
    return {"kind": "grafana_query_frames", "frames": frames[:15], "numeric_fields": series,
            "rows_examined_approximately": min(count, limit),
            "time_window": {"earliest": min(times), "latest": max(times)} if times else None}, [
                "Grafana frames are query results, not dashboard definitions. Each field may have distinct labels and units.",
                "Descriptive field summaries; no rates, joins, or cross-series arithmetic performed"]

def summarize_generic_json(payload):
    def shape(obj, depth=0):
        if depth >= 2:
            return type(obj).__name__
        if isinstance(obj, dict):
            return {safe_string(k): shape(v, depth + 1) for k, v in list(obj.items())[:20] if field_safe(k)}
        if isinstance(obj, list):
            return {"type": "list", "length": len(obj), "first_item_shape": shape(obj[0], depth + 1) if obj else None}
        return type(obj).__name__
    return {"kind": "unknown_json", "shape": shape(payload)}, ["Unknown observability schema: structure shown only; no metric/trace interpretation was assumed"]


def summarize_json(path, limit):
    # Standard json.load is not streaming; reject oversized JSON rather than risking OOM.
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError("JSON source exceeds 32 MiB on disk. Export JSONL/CSV or a smaller time window")
    with open_text(path) as handle:
        text = handle.read(MAX_JSON_BYTES + 1)
    if len(text.encode("utf-8")) > MAX_JSON_BYTES:
        raise ValueError("Decompressed JSON exceeds 32 MiB; split into smaller files")
    payload = json.loads(text)
    if isinstance(payload, dict):
        if isinstance(payload.get("dashboard"), dict) or ("panels" in payload and ("title" in payload or "templating" in payload)):
            return summarize_dashboard(payload)
        if isinstance(payload.get("data"), dict) and "resultType" in payload["data"]:
            return summarize_prometheus(payload, limit)
        if "resourceSpans" in payload or (isinstance(payload.get("data"), list) and any(isinstance(t, dict) and "spans" in t for t in payload["data"][:3])):
            return read_traces(payload, limit)
        if "resourceMetrics" in payload:
            return summarize_otel_metrics(payload, limit)
        if isinstance(payload.get("results"), dict) and any(isinstance(x, dict) and "frames" in x for x in payload["results"].values()):
            return summarize_grafana_frames(payload, limit)
    if isinstance(payload, list) and payload and isinstance(payload[0], dict) and "traceId" in payload[0] and "id" in payload[0]:
        return read_traces(payload, limit)
    return summarize_generic_json(payload)


def summarize_jsonl(path, limit):
    counts = collections.Counter()
    errors = 0
    rows = 0
    examples = []
    trace_summary = TraceSummary(limit)
    metric_names = collections.Counter()
    metric_values = []
    timestamps = []
    with open_text(path) as f:
        for line in f:
            if rows >= limit:
                break
            if not line.strip():
                continue
            rows += 1
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                errors += 1
                continue
            if not isinstance(obj, dict):
                continue
            for k in obj:
                if field_safe(k):
                    counts[safe_string(k)] += 1
            if len(examples) < 2:
                examples.append({safe_string(k): type(v).__name__ for k, v in list(obj.items())[:20] if field_safe(k)})
            trace_id = obj.get("trace_id") or obj.get("traceId")
            span_id = obj.get("span_id") or obj.get("spanId")
            if trace_id and span_id:
                duration = float_number(obj.get("duration_ms"))
                if duration is None and (n := float_number(obj.get("duration_us"))) is not None:
                    duration = n / 1000
                if duration is None and (n := float_number(obj.get("duration_ns"))) is not None:
                    duration = n / 1e6
                trace_summary.add(trace_id, span_id, obj.get("service") or obj.get("service_name"),
                                  obj.get("operation") or obj.get("name"), duration,
                                  obj.get("timestamp") or obj.get("start_time"),
                                  looks_error(obj.get("attributes") or obj.get("tags"), obj.get("status")))
            name = obj.get("__name__") or obj.get("metric") or obj.get("metric_name")
            if name:
                metric_names[safe_string(name)] += 1
                if (val := float_number(obj.get("value"))) is not None and len(metric_values) < 3000:
                    metric_values.append(val)
            if (stamp := time_iso(obj.get("timestamp") or obj.get("time"))):
                timestamps.append(stamp)
    if trace_summary.spans:
        output, warnings = trace_summary.output()
        output["kind"] = "trace_jsonl"
    elif metric_names:
        output = {"kind": "metrics_jsonl", "metric_names": bounded_counter(metric_names),
                  "numeric_values_sample": summary_numbers(metric_values),
                  "time_window": {"earliest": min(timestamps), "latest": max(timestamps)} if timestamps else None}
        warnings = ["Sample values are not aligned and may have different units or labels; no rates inferred"]
    else:
        output = {"kind": "jsonl_schema", "frequent_fields": bounded_counter(counts, 20), "sample_shapes": examples}
        warnings = ["No recognized metrics or spans fields; cannot infer observability semantics"]
    output["rows_examined"] = rows
    output["invalid_json_lines"] = errors
    warnings.append(f"Read at most {limit} nonempty lines; later lines may be omitted")
    return output, warnings


def main():
    parser = argparse.ArgumentParser(description="Offline, read-only metrics/dashboard/traces file inspector")
    parser.add_argument("--file", required=True, help="File under HOLMES_OBS_DATA_DIR")
    parser.add_argument("--max-rows", type=int, default=50000, help="Cap CSV/JSONL rows, Prom samples, or spans (100-200000)")
    args = parser.parse_args()
    try:
        if not (100 <= args.max_rows <= 200000):
            raise ValueError("--max-rows must be between 100 and 200000")
        path = accessible_path(args.file)
        suffix = Path(path.stem).suffix.lower() if path.suffix.lower() == ".gz" else path.suffix.lower()
        if suffix == ".csv":
            data, warnings = summarize_csv(path, args.max_rows)
        elif suffix in (".jsonl", ".ndjson"):
            data, warnings = summarize_jsonl(path, args.max_rows)
        elif suffix == ".json":
            data, warnings = summarize_json(path, args.max_rows)
        else:
            raise ValueError("Compressed file must end in .csv.gz, .json.gz, .jsonl.gz, or .ndjson.gz")
        print(json.dumps({"status": "ok", "file": path.name, "analysis": data, "warnings": warnings}, ensure_ascii=False, separators=(",", ":"), default=str))
    except (ValueError, OSError, UnicodeError, csv.Error, json.JSONDecodeError) as err:
        print(json.dumps({"status": "error", "error": safe_string(err, 250),
                          "hint": "Check path, mounted data directory, format and size. Do not paste the full file into the LLM."}, ensure_ascii=False))
        sys.exit(2)


if __name__ == "__main__":
    main()
