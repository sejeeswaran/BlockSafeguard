#!/usr/bin/env python3
"""
Automatic Contract Address & ABI Updater for BlockSafeguard
Updates the contract address and ABI in blockchain_logger.py
"""

import re
import json

def update_contract_address(new_address):
    """
    Update the contract address in blockchain_logger.py

    Args:
        new_address (str): The new contract address from Remix deployment
    """
    try:
        # Read the current blockchain_logger.py file
        with open('blockchain_logger.py', 'r') as file:
            content = file.read()

        # Find and replace the contract address
        old_address_pattern = r"contract_address = '[^']*'"
        new_address_line = f"contract_address = '{new_address}'"

        # Use regex to replace the contract address line
        updated_content = re.sub(old_address_pattern, new_address_line, content)

        # Write the updated content back
        with open('blockchain_logger.py', 'w') as file:
            file.write(updated_content)

        print(f"✅ Contract address updated to: {new_address}")
        return True

    except Exception as e:
        print(f"❌ Error updating contract address: {e}")
        return False

def update_contract_abi(new_abi_json):
    """
    Update the contract ABI in blockchain_logger.py

    Args:
        new_abi_json (str): The new ABI JSON string from Remix deployment
    """
    try:
        # Parse the ABI JSON to validate it
        try:
            abi_data = json.loads(new_abi_json)
            # Pretty format for better readability
            formatted_abi = json.dumps(abi_data, indent='\t')
        except json.JSONDecodeError:
            print("❌ Invalid ABI JSON format")
            return False

        # Read the current blockchain_logger.py file
        with open('blockchain_logger.py', 'r') as file:
            content = file.read()

        # Find the ABI section (between contract_abi = [ and the closing ])
        abi_pattern = r'(contract_abi = \[.*?\]\s*#.*?ABI here)'
        abi_match = re.search(abi_pattern, content, re.DOTALL)

        if not abi_match:
            print("❌ Could not find ABI section in blockchain_logger.py")
            return False

        # Create the new ABI section
        new_abi_section = f"""contract_abi = {formatted_abi}]  # Updated ABI from Remix deployment"""

        # Replace the old ABI section
        updated_content = content.replace(abi_match.group(1), new_abi_section)

        # Write the updated content back
        with open('blockchain_logger.py', 'w') as file:
            file.write(updated_content)

        print("✅ Contract ABI updated successfully")
        print(f"📊 ABI contains {len(abi_data)} functions/events")
        return True

    except Exception as e:
        print(f"❌ Error updating contract ABI: {e}")
        return False

def main():
    """Main function to get contract address and optionally ABI from user and update"""
    print("🔧 BlockSafeguard Contract Address & ABI Updater")
    print("=" * 55)

    # Get the contract address from user
    contract_address = input("Enter the deployed contract address from Remix IDE: ").strip()

    # Validate the address format (basic Ethereum address validation)
    if not contract_address.startswith('0x') or len(contract_address) != 42:
        print("❌ Invalid Ethereum address format. Address should start with '0x' and be 42 characters long.")
        return

    # Ask if user wants to update ABI too
    update_abi = input("Do you want to update the ABI as well? (y/N): ").strip().lower()

    abi_json = None
    if update_abi in ['y', 'yes']:
        print("\n📋 Paste your ABI JSON from Remix IDE (the full array):")
        print("💡 Tip: Copy from Remix 'Compile' tab → 'ABI' → Copy to clipboard")
        abi_json = input().strip()

    # Confirm with user
    print(f"\n📝 Summary of changes:")
    print(f"   • Contract Address: {contract_address}")
    if abi_json:
        print("   • ABI: Will be updated")
    else:
        print("   • ABI: No changes")

    confirm = input("\nProceed with updates? (y/N): ").strip().lower()

    if confirm in ['y', 'yes']:
        success_count = 0

        # Update contract address
        if update_contract_address(contract_address):
            success_count += 1
            print("✅ Contract address updated")
        else:
            print("❌ Contract address update failed")

        # Update ABI if requested
        if abi_json:
            if update_contract_abi(abi_json):
                success_count += 1
                print("✅ Contract ABI updated")
            else:
                print("❌ Contract ABI update failed")

        if success_count > 0:
            print(f"\n🎉 {success_count} update(s) completed successfully!")
            print("📋 Next steps:")
            print("   1. Restart your Flask application: python app.py")
            print("   2. Test the blockchain integration")
            print("   3. Check the status page for blocked IPs")
        else:
            print("\n❌ All updates failed")
    else:
        print("Operation cancelled.")

if __name__ == "__main__":
    main()