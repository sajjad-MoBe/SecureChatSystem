from src.phase1 import CA, User
from src.phase2 import diffie_hellman_exchange
from src.phase3 import encrypt_message, decrypt_message

def certificate_status(user, ca):
    if user is None or user.certificate is None:
        return "Not issued"
    if ca is None:
        return "Issued, CA unavailable"
    return "Issued and verified" if user.verify_certificate(user.certificate, ca.public_key) else "Issued but invalid"

def show_menu():
    print("==================================================")
    print("SECURE CRYPTOGRAPHY SYSTEM")
    print("==================================================")
    print("1. Initialize system (generate keys & certificates)")
    print("2. Establish shared key (DH exchange with authentication)")
    print("3. Encrypt a message (A -> B)")
    print("4. Decrypt a message (B)")
    print("5. Show current status")
    print("6. Exit")
    print("==================================================")

def main():
    ca = None
    user_a = None
    user_b = None
    master_key = None
    last_encrypted_blocks = None

    while True:
        show_menu()
        choice = input("Choice: ").strip()

        if choice == '1':
            print("\n[Phase 1] Initializing System...")
            ca = CA()
            print("  -> CA keys generated.")

            user_a = User("A")
            print("  -> User A keys generated.")

            user_b = User("B")
            print("  -> User B keys generated.")

            user_a.receive_certificate(ca)
            print("  -> Certificate issued for User A by CA.")

            user_b.receive_certificate(ca)
            print("  -> Certificate issued for User B by CA.")

            # Verify certificates
            if user_a.verify_certificate(user_a.certificate, ca.public_key):
                print("  -> User A's certificate verified successfully by User A.")
            if user_b.verify_certificate(user_b.certificate, ca.public_key):
                print("  -> User B's certificate verified successfully by User B.")

            print("Initialization Complete!\n")

        elif choice == '2':
            if ca is None or user_a is None or user_b is None:
                print("\nError: System not initialized. Please run option 1 first.\n")
                continue

            print("\n[Phase 2] Establishing Shared Key (Diffie-Hellman)...")
            try:
                master_key = diffie_hellman_exchange(user_a, user_b, ca.public_key)
                print(f"  -> Authentication and Key Exchange successful!")
                print(f"  -> Master Key Generated: {master_key}\n")
            except Exception as e:
                print(f"  -> Error during key exchange: {e}\n")

        elif choice == '3':
            if master_key is None:
                print("\nError: Master key not established. Please run option 2 first.\n")
                continue

            print("\n[Phase 3] Encrypting a message (A -> B)")
            message = input("Enter the message to encrypt: ")

            try:
                encrypted_blocks = encrypt_message(message, master_key)
                last_encrypted_blocks = encrypted_blocks
                print(f"  -> Message encrypted successfully!")
                print(f"  -> Encrypted Blocks: {encrypted_blocks}\n")
            except Exception as e:
                print(f"  -> Encryption failed: {e}\n")

        elif choice == '4':
            if master_key is None:
                print("\nError: Master key not established. Please run option 2 first.\n")
                continue

            print("\n[Phase 3] Decrypting a message (B)")
            blocks_input = input("Enter the encrypted blocks (comma separated, leave empty for last encrypted message): ").strip()
            try:
                if blocks_input:
                    blocks = [int(b.strip()) for b in blocks_input.split(',')]
                elif last_encrypted_blocks:
                    blocks = last_encrypted_blocks
                    print(f"  -> Using last encrypted blocks: {blocks}")
                else:
                    raise ValueError("No encrypted blocks were provided or stored")

                decrypted_message = decrypt_message(blocks, master_key)
                print(f"  -> Message decrypted successfully!")
                print(f"  -> Decrypted Message: {decrypted_message}\n")
            except Exception as e:
                print(f"  -> Decryption failed: {e}\n")

        elif choice == '5':
            print("\n--- Current System Status ---")
            if ca:
                print(f"CA Public Key: {ca.public_key}")
            else:
                print("CA Public Key: Not generated")

            if user_a:
                print(f"User A Public Key: {user_a.public_key}")
                print(f"User A Certificate Status: {certificate_status(user_a, ca)}")
            else:
                print("User A Public Key: Not generated")

            if user_b:
                print(f"User B Public Key: {user_b.public_key}")
                print(f"User B Certificate Status: {certificate_status(user_b, ca)}")
            else:
                print("User B Public Key: Not generated")

            print(f"Master Key: {master_key if master_key else 'Not generated'}")
            print(f"Last Encrypted Message Blocks: {last_encrypted_blocks if last_encrypted_blocks else 'None'}")
            print("-----------------------------\n")

        elif choice == '6':
            print("Goodbye!")
            break

        else:
            print("Invalid choice. Please select a valid option.\n")

if __name__ == "__main__":
    main()
