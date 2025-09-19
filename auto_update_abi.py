#!/usr/bin/env python3
"""
Fully Automated ABI Updater for BlockSafeguard
Automatically reads ABI from abi.json file and updates blockchain_logger.py
"""

import re
import json
import os

def load_abi_from_file(abi_file="abi.json"):
    """Load ABI from JSON file"""
    try:
        if not os.path.exists(abi_file):
            print(f"ABI file '{abi_file}' not found")
            return None

        with open(abi_file, 'r') as file:
            abi_data = json.load(file)

        print(f"Loaded ABI from {abi_file}")
        return abi_data

    except json.JSONDecodeError as e:
        print(f"Invalid JSON in {abi_file}: {e}")
        return None
    except Exception as e:
        print(f"Error reading {abi_file}: {e}")
        return None

def update_contract_abi(abi_data):
    """
    Update the contract ABI in blockchain_logger.py

    Args:
        abi_data: The ABI data (list of dicts)
    """
    try:
        # Format ABI with proper indentation
        formatted_abi = json.dumps(abi_data, indent='\t')

        # Read the current blockchain_logger.py file
        with open('blockchain_logger.py', 'r') as file:
            content = file.read()

        # Find the ABI section (between contract_abi = [ and the closing ])
        abi_pattern = r'(contract_abi = \[.*?\]\s*#.*?ABI.*functions?)'
        abi_match = re.search(abi_pattern, content, re.DOTALL)

        if not abi_match:
            print("Could not find ABI section in blockchain_logger.py")
            return False

        # Create the new ABI section
        new_abi_section = f"""contract_abi = {formatted_abi}]  # Auto-updated ABI from abi.json"""

        # Replace the old ABI section
        updated_content = content.replace(abi_match.group(1), new_abi_section)

        # Write the updated content back
        with open('blockchain_logger.py', 'w') as file:
            file.write(updated_content)

        print("Contract ABI updated successfully")
        print(f"ABI contains {len(abi_data)} functions/events")

        # Show what functions/events are available
        functions = [item for item in abi_data if item.get('type') == 'function']
        events = [item for item in abi_data if item.get('type') == 'event']

        if functions:
            func_names = [f['name'] for f in functions]
            print(f"Functions: {', '.join(func_names)}")
        if events:
            event_names = [e['name'] for e in events]
            print(f"Events: {', '.join(event_names)}")

        return True

    except Exception as e:
        print(f"Error updating contract ABI: {e}")
        return False

def create_abi_template():
    """Create a template abi.json file"""
    template_abi = [
        {
            "inputs": [
                {
                    "internalType": "string",
                    "name": "_ip",
                    "type": "string"
                },
                {
                    "internalType": "string",
                    "name": "_reason",
                    "type": "string"
                }
            ],
            "name": "addIP",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        }
    ]

    try:
        with open('abi.json', 'w') as file:
            json.dump(template_abi, file, indent=2)
        print("Created abi.json template file")
        print("Replace the content with your actual ABI from Remix IDE")
        return True
    except Exception as e:
        print(f"Error creating template: {e}")
        return False

def main():
    """Main function for fully automated ABI updates"""
    import sys

    # Check for command line arguments
    auto_confirm = '--yes' in sys.argv or '-y' in sys.argv

    print("BlockSafeguard Auto ABI Updater")
    print("=" * 40)

    # Check if abi.json exists
    if not os.path.exists('abi.json'):
        print("abi.json file not found")
        if auto_confirm:
            print("Auto-creating abi.json template...")
            create_template = 'y'
        else:
            try:
                create_template = input("Create abi.json template? (y/N): ").strip().lower()
            except EOFError:
                print("No user input available. Use --yes flag for automated mode.")
                return

        if create_template in ['y', 'yes']:
            if create_abi_template():
                print("\nNext steps:")
                print("   1. Copy ABI from Remix IDE (Compile -> ABI)")
                print("   2. Paste into abi.json file")
                print("   3. Run this script again")
                return
        else:
            print("No abi.json file - cannot proceed")
            return

    # Load ABI from file
    abi_data = load_abi_from_file()
    if not abi_data:
        return

    # Confirm update
    print(f"\nReady to update ABI with {len(abi_data)} items")

    if auto_confirm:
        confirm = 'y'
        print("Auto-confirming update (--yes flag used)")
    else:
        try:
            confirm = input("Proceed with ABI update? (y/N): ").strip().lower()
        except EOFError:
            print("No user input available. Use --yes flag for automated mode.")
            return

    if confirm in ['y', 'yes']:
        if update_contract_abi(abi_data):
            print("\nABI updated successfully!")
            print("Next steps:")
            print("   1. Restart Flask: python app.py")
            print("   2. Test new functions")
        else:
            print("\nABI update failed")
    else:
        print("Operation cancelled.")

if __name__ == "__main__":
    main()