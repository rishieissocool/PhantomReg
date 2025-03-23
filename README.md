
<h1 align="center">

<br>
<img src="https://i.imgur.com/T67NiRK.png">
<br>
Phantom Reg
</h1>

**PhantomReg** is a Python-based registry exploit generator designed to inject malicious payloads into the Windows startup process via the registry. It includes a base64-encoded PowerShell payload and optional obfuscation to evade detection by antivirus software.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Arguments](#arguments)
- [Example](#example)
- [License](#license)
- [Contributing](#contributing)
- [Screenshots](#screenshots)

---

## Overview

PhantomReg allows for the creation of registry files (`.reg`) that modify the Windows startup to run a malicious PowerShell script. The payload is encoded to evade detection, and the program offers an option for obfuscation, making it harder for security tools to detect the exploit.

The generated `.reg` file adds entries to the Windows registry (`Shell` and `Userinit`) to run a PowerShell command that executes a payload when the system starts. The script can be used for educational purposes or to simulate malware payloads in a controlled environment.

---

## Features

- **Base64-Encoded Payload**: The PowerShell script is base64-encoded to avoid detection by basic text-based scanners.
- **Obfuscation**: The payload can be obfuscated with random byte insertion, making it harder to detect by antivirus software.
- **Customizable Filename**: Choose a misleading name for the `.reg` file to make it harder to identify as malicious.
- **Support for Custom Payloads**: You can inject custom binary payloads into the registry file.

---

## Installation

1. **Clone the Repository**  
   Clone this repository to your local machine using Git:
   ```bash
   git clone https://github.com/<your-username>/PhantomReg.git
   ```

2. **Install Dependencies**  
   Make sure you have Python 3.x installed. You can install the necessary dependencies by running:
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

To generate a malicious registry payload, run the script with the desired options:

```bash
python phantom_reg.py <payload_file> --obfuscate --obf_length_kb <length> --reg_filename <filename> --misleading_name <name>
```

### Arguments

- **payload**: Path to the payload file to be embedded in the registry.
- **--obfuscate**: Optional flag to enable obfuscation of the payload.
- **--obf_length_kb**: Length of obfuscation in KB (default: 256 KB).
- **--reg_filename**: Specify the base name for the `.reg` file (default: `monkey.reg`).
- **--misleading_name**: Specify a misleading name for the `.reg` file (default: empty).

---

## Example

An example command to generate a malicious payload with 512 KB obfuscation and a custom filename would be:

```bash
python phantom_reg.py payload.exe --obfuscate --obf_length_kb 512 --reg_filename "malicious_payload.reg" --misleading_name "SUSPICIOUS FILE"
```

This will create a `.reg` file with the specified settings.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Contributing

Feel free to fork this repository, create pull requests, or open issues for discussion. Contributions are welcome!

---


