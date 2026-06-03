// SPDX-FileCopyrightText: 2026 KustoKing / SecM8
// SPDX-License-Identifier: Apache-2.0
//
// Kusto.Language strict-lint wrapper for `contentops lint --strict`.
//
// Contract (read by contentops.lint.strict.run_strict):
//
//   echo "<kql>" | dotnet kql_strict.dll [<kql-file>]
//
// Reads KQL from stdin when redirected (the Python caller path).
// Optional file path arg is a fallback for ad-hoc CLI testing.
// Emits one diagnostic per line on stdout:
//
//   <rule_id>\t<severity>\t<line>\t<message>
//
// Severity is one of error|warning|info. Exit 0 on success (any
// number of diagnostics); exit 2 on file-read failure (with error
// text on stderr). The Python caller surfaces a KQL000 advisory
// when this wrapper crashes.
//
// Schema loading (F1.1 + G1 follow-up):
//
// On startup the wrapper enumerates `schemas*.json` files next to its
// own DLL (in the published `tools/` directory). Each file may carry
// a database + a list of tables; the wrapper merges them into one
// Kusto.Language `GlobalState` and passes it to `ParseAndAnalyze`.
// Conventional layout:
//
//   schemas.json          — Sentinel-side tables, refreshed nightly
//                           from the LA workspace metadata API.
//   schemas_defender.json — Defender XDR tables, vendored from
//                           Microsoft Learn (tenant-invariant).
//
// When a table appears in more than one file, the first occurrence
// wins (alphabetical filename order — schemas_defender beats schemas).
// When no schema files are present the wrapper logs a single stderr
// advisory and falls back to no-schema mode so a missing baseline
// can't gate the lint pipeline.
//
// Severity promotion is opt-in via KQL_STRICT_PROMOTE_SEVERITY=1; see
// the loop further down.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Kusto.Language;
using Kusto.Language.Symbols;

// -----------------------------------------------------------------------
// Read KQL from stdin (Python caller path) or argv[0] (CLI fallback).
// -----------------------------------------------------------------------

string text;
if (Console.IsInputRedirected)
{
    text = Console.In.ReadToEnd();
}
else if (args.Length == 1)
{
    string path = args[0];
    try
    {
        text = File.ReadAllText(path);
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"failed to read {path}: {ex.Message}");
        return 2;
    }
}
else
{
    Console.Error.WriteLine(
        "usage: pipe KQL via stdin (or pass a file path as the single arg)");
    return 2;
}

// -----------------------------------------------------------------------
// Enumerate schemas*.json next to the DLL, merge tables into one
// GlobalState. Falls back to bare ADX globals if no file is present
// OR every file fails to load.
// -----------------------------------------------------------------------

GlobalState? globals = null;
bool schemasLoaded = false;
try
{
    globals = BuildGlobalsFromBaseDir(AppContext.BaseDirectory);
    schemasLoaded = globals != null;
    if (!schemasLoaded)
    {
        Console.Error.WriteLine(
            $"kql_strict: no schemas*.json found next to the DLL at " +
            $"{AppContext.BaseDirectory}; running in no-schema mode + " +
            "warning-only severity. Run `contentops upstream check-schemas " +
            "--write` to populate `schemas.json` (the Defender file is " +
            "vendored at `tools/kql_strict/schemas_defender.json`).");
    }
}
catch (Exception ex)
{
    Console.Error.WriteLine(
        $"kql_strict: schema load failed ({ex.Message}); falling back " +
        "to no-schema mode + warning-only severity.");
}

// -----------------------------------------------------------------------
// Parse + analyse + emit diagnostics.
// -----------------------------------------------------------------------

int[] lineStarts = ComputeLineStarts(text);
var code = globals != null
    ? KustoCode.ParseAndAnalyze(text, globals)
    : KustoCode.ParseAndAnalyze(text);

// Severity promotion is opt-in via env var. With a freshly-curated
// baseline shipped in PR-G, there are still gaps (e.g. FileProfile()
// invoke function, the InitiatingProcessVersionInfo* column family).
// Default keeps all wrapper findings at `warning` so CI doesn't gate
// on those gaps; once the nightly check-schemas workflow has expanded
// the baseline against the live tenant, flip
// KQL_STRICT_PROMOTE_SEVERITY=1 in lint.yml + validate.yml.
bool promoteSeverity = string.Equals(
    Environment.GetEnvironmentVariable("KQL_STRICT_PROMOTE_SEVERITY"),
    "1", StringComparison.Ordinal)
    || string.Equals(
        Environment.GetEnvironmentVariable("KQL_STRICT_PROMOTE_SEVERITY"),
        "true", StringComparison.OrdinalIgnoreCase);

foreach (var diag in code.GetDiagnostics())
{
    string codeStr = diag.Code ?? "";
    string ruleId = codeStr.Length > 0 ? codeStr : "KQL000";

    string severity = (schemasLoaded && promoteSeverity)
        ? MapSeverity(diag.Severity)
        : "warning";

    int line = OffsetToLine(diag.Start, lineStarts);
    string message = (diag.Message ?? string.Empty)
        .Replace('\t', ' ')
        .Replace('\n', ' ')
        .Replace('\r', ' ');
    Console.Out.WriteLine($"{ruleId}\t{severity}\t{line}\t{message}");
}
return 0;


// -----------------------------------------------------------------------
// Local functions
// -----------------------------------------------------------------------

static GlobalState? BuildGlobalsFromBaseDir(string baseDir)
{
    // Enumerate every `schemas*.json` file in the base dir. Sort
    // alphabetically so the merge order is deterministic; when a
    // table name appears in more than one file the first occurrence
    // (alphabetically) wins. Convention: `schemas_defender.json`
    // comes before `schemas.json` alphabetically? — actually
    // `schemas.json` < `schemas_defender.json`, so Sentinel wins
    // ties by default. The vendored Defender file carries the
    // canonical column list, so iterate Defender FIRST by sorting
    // by length-desc / name-desc to bias toward longer-named files.
    var files = Directory
        .GetFiles(baseDir, "schemas*.json")
        .OrderByDescending(p => Path.GetFileName(p), StringComparer.Ordinal)
        .ToArray();
    if (files.Length == 0) return null;

    string database = "schema";
    var byName = new Dictionary<string, TableSymbol>(StringComparer.Ordinal);

    foreach (var path in files)
    {
        try
        {
            (string fileDb, var fileTables) = LoadSchemaFile(path);
            if (database == "schema" && !string.IsNullOrEmpty(fileDb))
            {
                database = fileDb;
            }
            foreach (var t in fileTables)
            {
                // First-occurrence-wins. Earlier (alphabetically-later)
                // files take priority — that's the vendored
                // Defender file when it ships alongside schemas.json.
                if (!byName.ContainsKey(t.Name))
                {
                    byName[t.Name] = t;
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"kql_strict: skipping malformed schema file " +
                $"{Path.GetFileName(path)} ({ex.Message}).");
        }
    }

    if (byName.Count == 0) return null;
    var db = new DatabaseSymbol(database, byName.Values.ToArray());
    return GlobalState.Default.WithDatabase(db);
}


static (string Database, List<TableSymbol> Tables) LoadSchemaFile(string path)
{
    using var stream = File.OpenRead(path);
    using var doc = JsonDocument.Parse(stream);
    var root = doc.RootElement;
    if (root.ValueKind != JsonValueKind.Object)
    {
        return ("", new List<TableSymbol>());
    }

    string database = root.TryGetProperty("database", out var dbEl)
        && dbEl.ValueKind == JsonValueKind.String
        ? dbEl.GetString() ?? ""
        : "";

    var tables = new List<TableSymbol>();
    if (!root.TryGetProperty("tables", out var tablesEl)
        || tablesEl.ValueKind != JsonValueKind.Array)
    {
        return (database, tables);
    }

    foreach (var tableEl in tablesEl.EnumerateArray())
    {
        if (tableEl.ValueKind != JsonValueKind.Object) continue;
        if (!tableEl.TryGetProperty("name", out var nameEl)
            || nameEl.ValueKind != JsonValueKind.String) continue;
        string tableName = nameEl.GetString() ?? "";
        if (string.IsNullOrEmpty(tableName)) continue;

        var columns = new List<ColumnSymbol>();
        if (tableEl.TryGetProperty("columns", out var colsEl)
            && colsEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var colEl in colsEl.EnumerateArray())
            {
                if (colEl.ValueKind != JsonValueKind.Object) continue;
                if (!colEl.TryGetProperty("name", out var colNameEl)
                    || colNameEl.ValueKind != JsonValueKind.String) continue;
                if (!colEl.TryGetProperty("type", out var colTypeEl)
                    || colTypeEl.ValueKind != JsonValueKind.String) continue;
                string colName = colNameEl.GetString() ?? "";
                string colType = colTypeEl.GetString() ?? "";
                if (string.IsNullOrEmpty(colName) || string.IsNullOrEmpty(colType))
                {
                    continue;
                }
                columns.Add(new ColumnSymbol(colName, MapScalarType(colType)));
            }
        }
        tables.Add(new TableSymbol(tableName, columns));
    }

    return (database, tables);
}

static TypeSymbol MapScalarType(string typeName)
{
    // LA-flavoured type strings -> Kusto.Language ScalarTypes. Unknown
    // types fall through to `dynamic` so a stray column never breaks
    // the GlobalState build.
    return typeName.ToLowerInvariant() switch
    {
        "string" => ScalarTypes.String,
        "int" => ScalarTypes.Int,
        "long" => ScalarTypes.Long,
        "real" => ScalarTypes.Real,
        "double" => ScalarTypes.Real,
        "decimal" => ScalarTypes.Decimal,
        "bool" => ScalarTypes.Bool,
        "boolean" => ScalarTypes.Bool,
        "datetime" => ScalarTypes.DateTime,
        "date" => ScalarTypes.DateTime,
        "timespan" => ScalarTypes.TimeSpan,
        "guid" => ScalarTypes.Guid,
        "uniqueid" => ScalarTypes.Guid,
        "dynamic" => ScalarTypes.Dynamic,
        _ => ScalarTypes.Dynamic,
    };
}

static string MapSeverity(string? severity)
{
    return severity switch
    {
        "Error" => "error",
        "Warning" => "warning",
        "Suggestion" => "info",
        "Information" => "info",
        _ => "warning",
    };
}

static int[] ComputeLineStarts(string text)
{
    // 1-based line numbers; lineStarts[0] = 0 (start of line 1).
    var starts = new List<int> { 0 };
    for (int i = 0; i < text.Length; i++)
    {
        if (text[i] == '\n')
        {
            starts.Add(i + 1);
        }
    }
    return starts.ToArray();
}

static int OffsetToLine(int offset, int[] lineStarts)
{
    // Binary search for the largest lineStart <= offset.
    int lo = 0, hi = lineStarts.Length - 1, best = 0;
    while (lo <= hi)
    {
        int mid = (lo + hi) / 2;
        if (lineStarts[mid] <= offset)
        {
            best = mid;
            lo = mid + 1;
        }
        else
        {
            hi = mid - 1;
        }
    }
    return best + 1;
}
