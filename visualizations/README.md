# Visualizations

This directory is used for charts generated from local WIDS experiments.

To generate presentation-quality visualizations after collecting baseline data and building AP profiles, run:

```bash
sudo ./venv/bin/python3 scripts/generate_charts.py
```

Generated visualizations may include:

- Clock-skew distributions
- Beacon Information Element baselines
- Illustrative sequence-stream behavior
- Hybrid WIDS evidence-weight visualizations

## Privacy

The chart generator anonymizes access-point labels by default.

Real development charts are not committed to this repository because locally generated visualizations may contain environment-specific wireless information.

## Evaluation Note

Some figures, particularly the sequence-stream visualization, are synthetic illustrations intended to explain detector behavior and are not direct PCAP replays.
