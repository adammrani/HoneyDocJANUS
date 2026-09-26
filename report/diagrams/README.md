# JANUS report diagrams

The six Mermaid sources are the authoritative editable diagrams for the report.

| Source | Report figure | Purpose |
|---|---|---|
| `01-system-context.mmd` | `figures/system-context.png` | actors, trust boundary, and sensor roles |
| `02-generation-pipeline.mmd` | `figures/generation-pipeline.png` | input, code stage, token policy, and output |
| `03-detection-architecture.mmd` | `figures/detection-architecture.png` | full Wazuh and Canarytokens evidence flow |
| `04-interaction-sequence.mmd` | `figures/interaction-sequence.png` | chronological interaction and collection |
| `05-evidence-data-model.mmd` | `figures/evidence-data-model.png` | registry entities and evidence links |
| `06-deployment.mmd` | `figures/deployment.png` | concrete Windows, Docker, and provider deployment |

Export each source as a high-resolution PNG with the exact destination filename
above. The LaTeX source displays a labeled placeholder until the PNG exists, so
the report remains editable while figures are being prepared.

