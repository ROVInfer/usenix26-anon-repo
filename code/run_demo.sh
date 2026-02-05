#!/bin/bash

# =========================================================
# Run Script for USENIX Security Artifact Submission
# Mode: Sample/Demo (Kick-the-Tires)
# =========================================================

# Exit immediately if a command exits with a non-zero status
set -e
cd "$(dirname "$0")"

# Define Directories (Relative to code/ folder)
INPUT_DIR="../sample_input"
MID_DIR="../sample_mid"
OUTPUT_DIR="../sample_output"

echo "======================================================="
echo "   Starting Pipeline Demo (Kick-the-Tires)"
echo "   Target Date: 2025-08-04"
echo "======================================================="

# Ensure output directory exists
if [ ! -d "$OUTPUT_DIR" ]; then
    echo "[Init] Creating output directory: $OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR"
else
    echo "[Init] Output directory exists: $OUTPUT_DIR"
fi

echo "Preparation: downloading ribs..."
mkdir -p ../sample_input/rib/2025-08/ripe/rrc00
mkdir -p ../sample_input/rib/2025-08/routeviews/route-views3
wget -O ../sample_input/rib/2025-08/ripe/rrc00/bview.20250804.0800.gz https://data.ris.ripe.net/rrc00/2025.08/bview.20250804.0800.gz
wget -O ../sample_input/rib/2025-08/routeviews/route-views3/rib.20250804.0800.bz2 https://routeviews.org/route-views3/bgpdata/2025.08/RIBS/rib.20250804.0800.bz2
echo "Done."

# Step 1: Control Plane Analysis
echo ""
echo "[Step 1/5] Running Control Plane Analysis (fire_cp.py)..."
echo "Note: Parsing sample RIBs from RouteViews and RIPE RIS."
python3 fire_cp.py --input_dir "$INPUT_DIR" --output_dir "$OUTPUT_DIR"

# Step 2: Data Plane Analysis
echo ""
echo "[Step 2/5] Running Data Plane Analysis (fire_dp.py)..."
echo "Note: Using cached measurement data from $MID_DIR to skip active scanning."
python3 fire_dp.py --input_dir "$INPUT_DIR" --output_dir "$OUTPUT_DIR" --sample_mid_dir "$MID_DIR"

# Step 3: Preprocessing
echo ""
echo "[Step 3/5] Preprocessing Paths (preprocess_path.py)..."
python3 preprocess_path.py --input_dir "$INPUT_DIR" --output_dir "$OUTPUT_DIR"

# Step 4: MCMC Inference
echo ""
echo "[Step 4/5] Running MCMC Inference Model (mcmc_torch.py)..."
echo "Note: Running on CPU for demo sample (this may take ~5-10 mins)."
python3 mcmc_torch.py --input_dir "$INPUT_DIR" --output_dir "$OUTPUT_DIR"

# Step 5: Post-Processing
echo ""
echo "[Step 5/5] Post-processing Results (post_processing.py)..."
python3 post_process.py --input_dir "$INPUT_DIR" --output_dir "$OUTPUT_DIR"

echo ""
echo "======================================================="
echo "   Demo Completed Successfully!"
echo "   Results generated in: $OUTPUT_DIR"
echo "======================================================="
echo "To validate the FINAL paper results, please run:"
echo "python3 validate.py"
echo "======================================================="
