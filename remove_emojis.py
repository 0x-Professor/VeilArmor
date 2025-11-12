"""
Remove emojis from all markdown files to make documentation professional.
"""
import re
from pathlib import Path

# List of files to clean
files_to_clean = [
    "README.md",
    "README_COMPLETE.md",
    "GETTING_STARTED.md",
    "PROJECT_SUMMARY.md",
    "IMPLEMENTATION_SUMMARY.md",
    "INSTALLATION_GUIDE.md",
    "QUICK_INSTALL.md",
    "QUICKSTART.md"
]

def remove_emojis(text):
    """Remove emoji characters from text."""
    # Unicode emoji ranges
    emoji_pattern = re.compile(
        "["
        "\U0001F600-\U0001F64F"  # emoticons
        "\U0001F300-\U0001F5FF"  # symbols & pictographs
        "\U0001F680-\U0001F6FF"  # transport & map symbols
        "\U0001F1E0-\U0001F1FF"  # flags (iOS)
        "\U00002702-\U000027B0"
        "\U000024C2-\U0001F251"
        "\U0001F900-\U0001F9FF"  # Supplemental Symbols and Pictographs
        "\U0001FA70-\U0001FAFF"  # Symbols and Pictographs Extended-A
        "]+", 
        flags=re.UNICODE
    )
    return emoji_pattern.sub('', text)

def clean_file(filepath):
    """Clean emojis from a single file."""
    path = Path(filepath)
    if not path.exists():
        print(f"Skipping {filepath} - file does not exist")
        return
    
    print(f"Cleaning {filepath}...")
    
    # Read file
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Remove emojis
    cleaned_content = remove_emojis(content)
    
    # Write back
    with open(path, 'w', encoding='utf-8') as f:
        f.write(cleaned_content)
    
    print(f"  Cleaned {filepath}")

if __name__ == "__main__":
    print("Removing emojis from documentation files...\n")
    
    for file in files_to_clean:
        clean_file(file)
    
    print("\nAll documentation files cleaned successfully!")
