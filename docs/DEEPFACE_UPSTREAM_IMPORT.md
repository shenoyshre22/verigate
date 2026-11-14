# DeepFace upstream import

## Source and provenance

- Upstream: https://github.com/serengil/deepface
- Imported branch: `master`
- Imported commit: `4df8db1559ec63c8370d849ac2f2f9982725545e`
- Upstream package version in that snapshot: `0.0.105`
- Destination: `backend/external/deepface/`
- Upstream license: MIT; the original `LICENSE`, copyright notice, README, package metadata, tests, and project files are retained.

The import contains the 374 files tracked by the upstream snapshot. Its nested `.git` directory was removed so VERIGATE tracks the imported files normally. No upstream source files were edited. Generated Python caches were removed after the import smoke check.

## Included upstream structure

```text
backend/external/deepface/
├── deepface/                 # package API, modules, models, database adapters, REST/gRPC API
├── tests/                    # upstream unit and integration tests and their fixtures
├── benchmarks/               # upstream evaluation notebooks
├── experiments/              # upstream experiment notebooks
├── docker/                   # upstream Docker and database examples
├── scripts/                  # upstream service and release scripts
├── setup.py
├── requirements_*.txt        # upstream dependency groups
├── README.md
├── LICENSE
└── package_info.json
```

## Dependency boundary

DeepFace declares its own install metadata and dependency groups. Its base set includes ONNX Runtime, OpenCV, NumPy, pandas, gdown, and RetinaFace; TensorFlow, PyTorch, API, CLI, and gRPC requirements are separate extras. Some optional detector/model paths add large native packages. These dependencies have not been merged into `backend/requirements.txt`.

The upstream package does not pin a single exact version set. No dependency resolver run was performed, so compatibility of every optional extra with VERIGATE's Python 3.13 local environment has not been established. The source metadata requires Python 3.8 or later; the Lambda template currently targets Python 3.12.

Use a separate virtual environment when evaluating the source:

```powershell
py -m venv .venv-deepface
.\.venv-deepface\Scripts\Activate.ps1
Set-Location backend\external\deepface
python -m pip install -e .
```

The optional extras are documented by upstream, for example `python -m pip install -e ".[tensorflow]"`. Install only the chosen backend and detector requirements in the isolated environment.

## Verification status

The source tree, package entry points, setup metadata, database adapters, model registry, and license were inspected. A direct package import was attempted from the current Python environment and stopped because `gdown` is not installed. Model weights are not included in the repository and were not downloaded. No DeepFace model inference or AWS operation was performed.

To update the vendored snapshot, fetch a specific upstream commit, record its full SHA here, compare the diff, and retain the upstream license and attribution. Do not edit `backend/external/deepface/deepface/` for VERIGATE-specific behavior; put adapters in VERIGATE-owned modules.
