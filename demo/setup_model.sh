#!/bin/bash

echo "=========================================="
echo "Copying XGBoost Model to Shared Folder"
echo "=========================================="

# Create models directory if it doesn't exist
mkdir -p ./shared/models

# Copy the 30-feature XGBoost model (best performance)
if [ -f "../model/xg_30_model.pkl" ]; then
    cp ../model/xg_30_model.pkl ./shared/models/model.pkl
    echo "✓ Copied xg_30_model.pkl to shared/models/model.pkl"
    
    # Also copy scaler and feature list for reference
    if [ -f "../model/scaler.pkl" ]; then
        cp ../model/scaler.pkl ./shared/models/
        echo "✓ Copied scaler.pkl"
    fi
    
    if [ -f "../model/feature_list.pkl" ]; then
        cp ../model/feature_list.pkl ./shared/models/
        echo "✓ Copied feature_list.pkl"
    fi
    
    echo ""
    echo "Model size:"
    ls -lh ./shared/models/model.pkl
    echo ""
    echo "✓ Model setup complete!"
else
    echo "✗ ERROR: Model file not found at ../model/xg_30_model.pkl"
    echo "Please train the model first using rf_model.ipynb"
    exit 1
fi

echo "=========================================="
