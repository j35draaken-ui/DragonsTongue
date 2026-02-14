import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import textwrap

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    _COLOR_AVAILABLE = True
except Exception:
    _COLOR_AVAILABLE = False
    class FakeFore:
        def __getattr__(self, name):
            return ""
    Fore = FakeFore()
    Style = FakeFore()

try:
    import pyfiglet
    _FIGLET_AVAILABLE = True
except Exception:
    _FIGLET_AVAILABLE = False


def print_banner():
            dragon_art = textwrap.dedent("""
                                                                                                                                 
                                                                                                                                 
                                                                                                                                 
                                                                                                                                 
                                                                                                                                 
                                                                                                                                 
                                                                                                                                 
                                                                                                                                 
                                                                                                          :.        R
                                                                                       r                 BB       :BQ
                                                                                     bB.              iBBd      .QBBB
                                                                                  YBBB             rQBBD      YBBBQB
                                                                           rBBrEBBBB:      7B. rdBBBBi   .vEBBBQBBB
                                                                    .    ZBBBBBBBQ:   :UMBBBBBBBBBBBbPQBBBBBBBBBQS
                                                                  .B7  EBBBQQQBBBBBQBBBBBBBBBQBBBBBBBQBBBBBBBQB1
                                                                 vQB. YIrrrrr7rr:ir1dBQBBBQBBBBBBBBBBBBBBBBBP:
                                                               .BQBBRgBBBBBQBBQUr.      .7DBBBBQBBBBBQBBQs.
                                                             .DBBBQBQBBBBBB1                 :1BBBBBSr
                                                           :BBBQBQBgUQBBBBL       .7mqmvr:.
                                                        igQBBBBBP: .PBBBBBQ: .i5BBQdrir5bgbKLr.
                                             mU       UBBBBBgi    .dBBBBBBBBBBBBB: .uDqr.
                                           SB:     iMBBB7         uBBBBBQBBBBBBBBBBBBBBBB
                                          BBB.:rmBBBBQ:        :IQBQBBBBBBBBBBBBBBBBBBZIv:
                                         RBBBBQBBBBBr.vBBBBBBBBBBBBBBBQBBBBBBBBBBBQBBBBBBBBBg:
                                         BBBBBBBBQQuPBBBBBBBBBBBBBBBr    .EQBBBBBBBBBQBBBQBBBBBI
                                        7BBBQBBBBBBBBBBBBBBBBBBBBq .  ImKvrRBBBBBBBBBBB:     .qBB:
                                        LBBQBBBBBBBBBBBBBB:    7i   .QBBBBBBBBBBBBBQBBB:        LBv
                                        .BBBBBQBBBBBBBBB1    :    :BBBBBBBBBBBBBBBBBBBBBBBQBQ:    Q:
                                         QBBB7rB:::IBr.     sBDi7qBBBBBBBBBBBBBBBBBBB7...:YgBBB1   .
                                         rBBR          .J.BBBBBBBBBBQBBBBBBBBBBBBBBB          7BBi
                                          j    r  .B   7BBBBBBBBBQBBBQBBBBBBBQBBBQBBD           .J.
                                            r .BBDMBBBBBBBBBBBBBQBBBBBBBBBBBBBBBBBBBQBP:
                                            BQBBBBBBBQBBBBBQBBBBBBBBBBBBBBBBBBBBBBBBBBBQBJ
                                           iBBBBBBBBBBBBBBBBBBBBgBBBBBBBQBQBBBBBBBBBBBBBBBB
                                             2s BQBBBBBBBBK:   . .BEgBBBBBBBBBBBBBBI. .iEQBB
                                                qBQBBBQBBB:       B  ZBBBQ. 7BQBBBB       7BB
                                                 BBBBBBg57:           BQB     rBBQBB.       Q
                                                  rEQBBq.             bB:       PBBBBBBIr.
                                                                      sB          1BBBBBbi
                                                                      .:
            """)
            if _COLOR_AVAILABLE:
                print(f"{Fore.GREEN}{dragon_art}{Style.RESET_ALL}")
            else:
                print(dragon_art)

            if _FIGLET_AVAILABLE:
                try:
                    word = pyfiglet.figlet_format(" D R A G O N  T O N G U E", font="larry3d")
                    if _COLOR_AVAILABLE:
                        print(f"{Fore.GREEN}{word}{Style.RESET_ALL}")
                    else:
                        print(word)
                except Exception:
                    if _COLOR_AVAILABLE:
                        print(f"{Fore.CYAN}Welcome to AES-256 Encryption/Decryption{Style.RESET_ALL}")
                    else:
                        print("Welcome to AES-256 Encryption/Decryption")
def save_key_hex(key: bytes, filename: str = 'aes_key.hex'):
    with open(filename, 'w') as f:
        f.write(key.hex())
    if _COLOR_AVAILABLE:
        print(f"{Fore.GREEN}✓ Saved key to {Fore.CYAN}{filename}{Style.RESET_ALL}")


def load_key_hex(filename: str = 'aes_key.hex') -> bytes:
    if not os.path.exists(filename):
        raise FileNotFoundError(f"Saved key file '{filename}' not found")
    with open(filename, 'r') as f:
        hexdata = f.read().strip()
    return bytes.fromhex(hexdata)

# Function to encrypt a file using AES-256
def encrypt_file(file_path: str, key: bytes):
    if _COLOR_AVAILABLE:
        print(f"{Fore.MAGENTA}→ Encrypting file: {Fore.CYAN}{file_path}{Style.RESET_ALL}")
    else:
        print(f"Encrypting file: {file_path}")
    # Open the file in binary read mode ('rb')
    with open(file_path, 'rb') as file:
        data = file.read()  # Read the content of the file
    
    # Generate a random IV (16 bytes)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the data to ensure it's a multiple of the block size (16 bytes for AES)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt the padded data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Return IV + encrypted data to store together
    return iv + encrypted_data

# Function to decrypt a file using AES-256
def decrypt_file(file_path: str, key: bytes):
    if _COLOR_AVAILABLE:
        print(f"{Fore.MAGENTA}→ Decrypting file: {Fore.CYAN}{file_path}{Style.RESET_ALL}")
    else:
        print(f"Decrypting file: {file_path}")
    # Open the encrypted file in binary read mode ('rb')
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()  # Read the encrypted data
    
    # Extract the IV (first 16 bytes) and the encrypted content (remaining bytes)
    iv = encrypted_data[:16]
    encrypted_content = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_data = decryptor.update(encrypted_content) + decryptor.finalize()

    # Unpad the decrypted data using the same padding scheme as encryption
    unpadder = padding.PKCS7(128).unpadder()
    original_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return original_data


def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data


def decrypt_bytes(iv_and_encrypted: bytes, key: bytes) -> bytes:
    iv = iv_and_encrypted[:16]
    encrypted_content = iv_and_encrypted[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_content) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    original_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return original_data

# Main function to manage the flow
def main():
    print_banner()
    print()

    def display_menu():
        if _COLOR_AVAILABLE:
            print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Available Actions:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}  1{Style.RESET_ALL} - Encrypt File")
            print(f"{Fore.GREEN}  2{Style.RESET_ALL} - Decrypt File")
            print(f"{Fore.GREEN}  3{Style.RESET_ALL} - Encrypt Multiline Input")
            print(f"{Fore.GREEN}  4{Style.RESET_ALL} - Decrypt Multiline Input")
            print(f"{Fore.GREEN}  5{Style.RESET_ALL} - Exit")
            print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        else:
            print("="*60)
            print("Available Actions:")
            print("  1 - Encrypt File")
            print("  2 - Decrypt File")
            print("  3 - Encrypt Multiline Input")
            print("  4 - Decrypt Multiline Input")
            print("  5 - Exit")
            print("="*60)

    while True:
        display_menu()
        action = input(f"{Fore.YELLOW}Choose action (1-5): {Style.RESET_ALL}").strip() if _COLOR_AVAILABLE else input("Choose action (1-5): ").strip()

        def choose_key_for_action(save_new_default: bool = False) -> bytes:
            if _COLOR_AVAILABLE:
                print(f"{Fore.CYAN}Key options:{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}1{Style.RESET_ALL} - Generate new key and save")
                print(f"  {Fore.GREEN}2{Style.RESET_ALL} - Reuse saved key (aes_key.hex)")
                print(f"  {Fore.GREEN}3{Style.RESET_ALL} - Enter key hex manually")
            else:
                print("Key options:")
                print("  1 - Generate new key and save")
                print("  2 - Reuse saved key (aes_key.hex)")
                print("  3 - Enter key hex manually")
            opt = input(f"{Fore.YELLOW}Choose key option (1/2/3): {Style.RESET_ALL}").strip() if _COLOR_AVAILABLE else input("Choose key option (1/2/3): ").strip()
            if opt == '1':
                key = generate_key()
                save_key_hex(key)
                if _COLOR_AVAILABLE:
                    print(f"{Fore.GREEN}✓ Key saved{Style.RESET_ALL}")
                else:
                    print("Saved generated key to aes_key.hex")
                return key
            elif opt == '2':
                try:
                    key = load_key_hex()
                    if _COLOR_AVAILABLE:
                        print(f"{Fore.GREEN}✓ Loaded key from aes_key.hex{Style.RESET_ALL}")
                    else:
                        print("Loaded key from aes_key.hex")
                    return key
                except FileNotFoundError:
                    if _COLOR_AVAILABLE:
                        print(f"{Fore.RED}✗ Saved key not found.{Style.RESET_ALL}")
                        hex_in = input(f"{Fore.YELLOW}Enter the AES-256 key in hex format: {Style.RESET_ALL}")
                    else:
                        print("Saved key not found. Please enter key hex manually.")
                        hex_in = input("Enter the AES-256 key in hexadecimal format: ")
                    return bytes.fromhex(hex_in.strip())
            else:
                hex_in = input(f"{Fore.YELLOW}Enter the AES-256 key in hex format: {Style.RESET_ALL}").strip() if _COLOR_AVAILABLE else input("Enter the AES-256 key in hexadecimal format: ")
                return bytes.fromhex(hex_in.strip())

        if action == '1':
            if _COLOR_AVAILABLE:
                print(f"{Fore.CYAN}▶ Starting Encryption (File){Style.RESET_ALL}")
            else:
                print("Starting Encryption (File) Process...")
            key = choose_key_for_action(save_new_default=True)
            file_path = input("Enter the file path to encrypt: ")
            if _COLOR_AVAILABLE:
                print(f"{Fore.MAGENTA}→ File to encrypt: {Fore.CYAN}{file_path}{Style.RESET_ALL}")
            else:
                print(f"File to encrypt: {file_path}")
            encrypted_data = encrypt_file(file_path, key)
            with open(file_path + '.enc', 'wb') as enc_file:
                enc_file.write(encrypted_data)
            if _COLOR_AVAILABLE:
                print(f"{Fore.GREEN}✓ Encrypted file saved as {Fore.CYAN}{file_path}.enc{Style.RESET_ALL}")
            else:
                print(f"Encrypted file saved as {file_path}.enc")
            print()
            continue

        elif action == '2':
            if _COLOR_AVAILABLE:
                print(f"{Fore.CYAN}▶ Starting Decryption (File){Style.RESET_ALL}")
            else:
                print("Starting Decryption (File) Process...")
            key = choose_key_for_action()
            file_path = input("Enter the file path to decrypt: ")
            try:
                decrypted_data = decrypt_file(file_path, key)
                with open(file_path + '.dec', 'wb') as dec_file:
                    dec_file.write(decrypted_data)
                if _COLOR_AVAILABLE:
                    print(f"{Fore.GREEN}✓ Decrypted file saved as {Fore.CYAN}{file_path}.dec{Style.RESET_ALL}")
                else:
                    print(f"Decrypted file saved as {file_path}.dec")
            except Exception as e:
                if _COLOR_AVAILABLE:
                    print(f"{Fore.RED}✗ Decryption failed: {e}{Style.RESET_ALL}")
                else:
                    print(f"Decryption failed: {e}")
            print()
            continue

        elif action == '3':
            if _COLOR_AVAILABLE:
                print(f"{Fore.CYAN}▶ Encrypting multiline input{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}End with 'EOF' or Ctrl+Z{Style.RESET_ALL}")
            else:
                print("Encrypting multiline input. End input with a line containing only 'EOF' or strg + Z.")
            key = choose_key_for_action(save_new_default=True)
            if _COLOR_AVAILABLE:
                print(f"{Fore.GREEN}Enter text:{Style.RESET_ALL}")
            else:
                print("Enter text:")
            lines = []
            while True:
                try:
                    line = input()
                except EOFError:
                    break
                if line == 'EOF':
                    break
                lines.append(line)
            text = '\n'.join(lines)
            encrypted = encrypt_bytes(text.encode('utf-8'), key)
            b64 = base64.b64encode(encrypted).decode('ascii')
            if _COLOR_AVAILABLE:
                print(f"{Fore.GREEN}✓ Encrypted output (base64):{Style.RESET_ALL}")
            else:
                print("Encrypted output (base64):")
            print(b64)
            print()
            continue

        elif action == '4':
            if _COLOR_AVAILABLE:
                print(f"{Fore.CYAN}▶ Decrypting multiline/base64 input{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}End with 'EOF' or Ctrl+Z{Style.RESET_ALL}")
            else:
                print("Decrypting multiline/base64 input. End input with a line containing only 'EOF' or strg + Z.")
            key = choose_key_for_action()
            if _COLOR_AVAILABLE:
                print(f"{Fore.GREEN}Paste base64 encrypted input:{Style.RESET_ALL}")
            else:
                print("Paste base64 encrypted input:")
            lines = []
            while True:
                try:
                    line = input()
                except EOFError:
                    break
                if line == 'EOF':
                    break
                lines.append(line)
            b64 = ''.join(lines).strip()
            try:
                encrypted = base64.b64decode(b64)
                original = decrypt_bytes(encrypted, key)
                try:
                    if _COLOR_AVAILABLE:
                        print(f"{Fore.GREEN}✓ Decrypted text:{Style.RESET_ALL}")
                    else:
                        print("Decrypted text:")
                    print(original.decode('utf-8'))
                except UnicodeDecodeError:
                    if _COLOR_AVAILABLE:
                        print(f"{Fore.YELLOW}Decrypted data is binary; writing to 'output.dec'.{Style.RESET_ALL}")
                    else:
                        print("Decrypted data is binary; writing to 'output.dec'.")
                    with open('output.dec', 'wb') as f:
                        f.write(original)
            except Exception as e:
                if _COLOR_AVAILABLE:
                    print(f"{Fore.RED}✗ Decryption failed: {e}{Style.RESET_ALL}")
                else:
                    print(f"Decryption failed: {e}")
            print()
            continue

        elif action == '5':
            if _COLOR_AVAILABLE:
                print(f"{Fore.CYAN}Goodbye!{Style.RESET_ALL}")
            else:
                print("Goodbye!")
            break

        else:
            if _COLOR_AVAILABLE:
                print(f"{Fore.RED}✗ Invalid action. Please choose 1-5.{Style.RESET_ALL}")
            else:
                print("Invalid action. Please choose 1-5.")
            print()
            continue

if __name__ == "__main__":
    main()
