
This artifact implements a Bayesian inference model to estimate ROV enforcement
probabilities at the interface level.

--------------------------------------------------------------------------------
1. REPOSITORY STRUCTURE
--------------------------------------------------------------------------------

- code/
  Source code for the pipeline (Control Plane, Data Plane, MCMC Inference).

- sample_input/
  A subset of input data (RIBs, PeeringDB, AS Relationships) for the Demo.
  Note that due to file size limits, the BGP dataset must be downloaded 
  before running the demo. This step is integrated into run_demo.sh, 
  so no manual action is required.

- sample_mid_data/
  Cached active measurement results (Atlas traceroutes, Nmap scans) used to 
  bypass time-consuming measurements during the Demo.

- sample_output/
  Directory where Demo results will be generated.

- data/
  The full-scale final results (for validation).

- Dockerfile & requirements.txt
  Configuration files for the containerized environment.

--------------------------------------------------------------------------------
2. GETTING STARTED (DOCKER RECOMMENDED)
--------------------------------------------------------------------------------
We strongly recommend using Docker to ensure all system dependencies (e.g., nmap)
and Python libraries are correctly configured.

[PREREQUISITES]
- Docker Engine
- NVIDIA Container Toolkit (Only required for full reproduction with GPU)

Run the following command in the root directory:

    docker build -t usenix-artifact .

--------------------------------------------------------------------------------
3. EXPERIMENT WORKFLOW
--------------------------------------------------------------------------------

We provide three levels of reproduction:

[LEVEL 1: KICK-THE-TIRES (FAST DEMO)]
Goal: Verify that the pipeline runs without errors on a small sample dataset.
Time: ~10-15 minutes (CPU only).

Command:
    docker run --rm usenix-artifact

What happens inside:
1. Control Plane Analysis (fire_cp.py)
2. Data Plane Analysis (fire_dp.py) - Uses cached measurement data.
3. Preprocessing (preprocess_path.py)
4. MCMC Inference (mcmc_torch.py) - Runs on CPU.
5. Post-processing (post_processing.py)
Success Indicator: The script finishes with "Demo Completed Successfully!".

[LEVEL 2: VALIDATE PAPER RESULTS (INSTANT)]
Goal: Reproduce the statistics/figures in the paper using pre-computed full data.
Time: < 1 minute.

Command:
(Note: We use 'bash -c' to navigate to the code directory first)

    docker run --rm -v $(pwd)/data:/app/data usenix-artifact bash -c "cd code && python3 validate.py"

Expected Output:
- Console output showing counts of ROV/Non-ROV interfaces.
- Validation plots generated in the 'data/' folder on your host machine.

[LEVEL 3: FULL REPRODUCTION (OPTIONAL)]
Goal: Re-run inference on the full dataset.
Time: ~2 hours (Requires NVIDIA GPU).
Note: This requires downloading raw RIB data (not included due to size).

Command:
1. Verify GPU visibility:
    docker run --rm --gpus all usenix-artifact nvidia-smi

2. Run Inference:
    docker run --rm --gpus all -v $(pwd)/data:/app/data usenix-artifact python3 code/mcmc_torch.py --input_dir [PATH_TO_FULL_DATA] --output_dir data/

--------------------------------------------------------------------------------
4. SCRIPT DESCRIPTIONS (Inside code/ folder)
--------------------------------------------------------------------------------

- fire_cp.py
  Control Plane Measurements.

- fire_dp.py
  Data Plane Measurements.

- preprocess_path.py
  Preprocessing: Cleans raw data and builds the path matrix for inference.

- mcmc_torch.py
  Inference Engine: Bayesian model implemented in PyTorch.

- post_process.py
  Classification: Converts MCMC posterior probabilities into ROV labels.

- validate.py
  Validation: Compares results against Cloudflare, DP-strict.

- run_demo.sh
  The automated script that orchestrates the Level 1 Demo.

================================================================================
END OF README
================================================================================
