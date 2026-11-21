"""M6 speedtest analytics inside the collector (12-speedtest-analytics.md, 01-contracts.md section 14).

Modules: ``schema`` (SQLite migration), ``settings`` (config + tunables), ``diagnosis`` (the section 5.3 rules),
``privacy`` (scrub / redaction), ``repo`` (SQLite access), ``service`` (ingest, evidence, query, purge, retention),
``metrics`` (VictoriaMetrics histograms), ``stream`` (SSE) and ``api`` (HTTP handlers). Importing the package
imports nothing heavy: ``store`` pulls ``schema`` in for the migration.
"""
