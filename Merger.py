import pandas as pd
import re
import os
import glob
from sklearn.model_selection import train_test_split

# Define paths to your files based on current directory structure
# Get Noriben CSV files from OUTPUT directory
output_dir = "OUTPUT"
csv_files = glob.glob(os.path.join(output_dir, "*.csv"))

# Get registry snapshot files
reg_files = [f for f in glob.glob("~res-x64*.txt")]

# Create a list of file pairs
files = []
for i, csv_file in enumerate(csv_files):
    # Use corresponding registry file if available, otherwise use the first one
    reg_file = reg_files[min(i, len(reg_files)-1)] if reg_files else None
    
    # Extract malware number from csv filename (assuming each CSV corresponds to a different malware)
    csv_basename = os.path.basename(csv_file)
    
    # Try to determine which malware sample this corresponds to
    malware_num = i + 1
    
    files.append({
        "csv": csv_file, 
        "txt": reg_file, 
        "label": malware_num,
        "name": csv_basename
    })

print(f"Found {len(files)} file pairs for analysis:")
for file_info in files:
    print(f"  CSV: {file_info['csv']}, REG: {file_info['txt']}, Label: {file_info['label']}")

# Function to extract features from CSV
def extract_csv_features(csv_path):
    try:
        # Read CSV file
        df = pd.read_csv(csv_path)
        features = {}
        
        # Basic features
        features["total_operations"] = len(df)
        features["unique_processes"] = df["Process Name"].nunique()
        features["unique_paths"] = df["Path"].nunique()
        
        # Count operations by type
        op_counts = df["Operation"].value_counts().to_dict()
        for op, count in op_counts.items():
            features[f"op_{op}"] = count
        
        # Count results
        result_counts = df["Result"].value_counts().to_dict()
        for res, count in result_counts.items():
            features[f"result_{res}"] = count
            
        # Count operations by process - focus on top processes
        proc_counts = df["Process Name"].value_counts().head(10).to_dict()
        for proc, count in proc_counts.items():
            # Remove spaces and special chars to make valid feature names
            proc_name = re.sub(r'\W+', '_', proc)
            features[f"proc_{proc_name}"] = count
            
        return features
    except Exception as e:
        print(f"Error processing CSV {csv_path}: {e}")
        return {}

# Function to extract features from TXT (registry changes)
def extract_txt_features(txt_path):
    features = {}
    try:
        if txt_path is None:
            return features
            
        with open(txt_path, 'r') as f:
            content = f.read()
            
            # Extract numerical values using regex
            patterns = {
                "keys_deleted": r"Keys deleted: (\d+)",
                "keys_added": r"Keys added: (\d+)",
                "values_deleted": r"Values deleted: (\d+)",
                "values_added": r"Values added: (\d+)",
                "values_modified": r"Values modified: (\d+)",
                "total_changes": r"Total changes: (\d+)"
            }
            for key, pattern in patterns.items():
                match = re.search(pattern, content)
                features[key] = int(match.group(1)) if match else 0
                
            # Count registry key patterns of interest
            patterns_of_interest = [
                # System locations commonly modified by malware
                (r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "reg_autorun"),
                (r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "reg_user_autorun"),
                (r"HKLM\\SYSTEM\\ControlSet", "reg_system_control"),
                (r"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "reg_win_nt"),
                (r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer", "reg_explorer")
            ]
            
            for pattern, feature_name in patterns_of_interest:
                matches = re.findall(pattern, content)
                features[feature_name] = len(matches)
                
        return features
    except Exception as e:
        print(f"Error processing TXT {txt_path}: {e}")
        return {}

# Process all files and combine into a single dataset
data = []
for file_info in files:
    # Extract features
    csv_features = extract_csv_features(file_info["csv"])
    txt_features = extract_txt_features(file_info["txt"])
    
    # Combine features and add malware label
    row = {**csv_features, **txt_features, "malware": file_info["label"], "filename": file_info["name"]}
    data.append(row)

# Convert to DataFrame
df = pd.DataFrame(data)

# Fill null values with 0
df = df.fillna(0)

# Display information about the dataset
print(f"Dataset created with {len(df)} samples and {len(df.columns)} features")
print("Sample distribution:")
print(df["malware"].value_counts())

# Get feature columns (exclude 'malware' and 'filename')
feature_cols = [col for col in df.columns if col not in ['malware', 'filename']]

# If we have enough samples, split into training and test sets
if len(df) >= 2:
    # Split into training (75%) and test (25%) sets
    train_df, test_df = train_test_split(
        df,
        test_size=max(1, int(len(df) * 0.25)),  # At least one sample for test
        random_state=42  # Ensure reproducibility
    )

    # Verify the split
    print("Training set malware counts:\n", train_df["malware"].value_counts())
    print("Test set malware counts:\n", test_df["malware"].value_counts())

    # Save to CSV
    train_df.to_csv("training.csv", index=False)
    test_df.to_csv("test.csv", index=False)
    print("Training dataset saved to training.csv")
    print("Test dataset saved to test.csv")
else:
    # Not enough samples to split, save all as training
    df.to_csv("dataset.csv", index=False)
    print("Dataset saved to dataset.csv (not enough samples to split)")

# Save a feature list for reference
with open("feature_list.txt", "w") as f:
    f.write("Feature List:\n")
    for col in feature_cols:
        f.write(f"- {col}\n")
    
print(f"Feature list saved to feature_list.txt ({len(feature_cols)} features)")