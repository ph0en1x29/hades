# Benchmark Manifest

Primary manifest file: `data/manifests/public_benchmark_of_record.yaml`

## Public Benchmark of Record

- Dataset source: Splunk Attack Data
- Rule source: Splunk Security Content
- Access tier: public
- Role: first reproducible validation benchmark for Hades
- Transform version: `alert_projection_v2`

## Selected Scenario Slice

- Windows credential access
- Windows discovery
- Windows lateral movement

## Expected Raw Artifacts

- Windows Security logs
- Sysmon events
- Splunk detection content
- MITRE ATT&CK mapping metadata

## Known Limitations

- The first slice is technique-oriented rather than a full enterprise campaign benchmark
- Splunk-specific detections require normalization into the Hades alert contract
- SOC-Bench remains a stronger strategic benchmark but is not assumed public

## Repo Fixture

- Runnable public benchmark slice fixture: `data/benchmarks/public/splunk_attack_data_windows.jsonl`
