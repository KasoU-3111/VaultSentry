"""
VaultSentry - Safe Test Sample Generator
Generates harmless synthetic samples to verify scanner detections.
"""

import os
import random
from pathlib import Path

SAMPLES_DIR = Path(__file__).resolve().parent / "samples"
SAMPLES_DIR.mkdir(parents=True, exist_ok=True)

def generate_samples():
    # 1. Safe EICAR Test Sample (Signature Detection)
    eicar_path = SAMPLES_DIR / "sample_eicar.com"
    eicar_string = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    eicar_path.write_text(eicar_string)
    print(f"[+] Created: {eicar_path.name}")

    # 2. Spoofed Extension Sample (MZ Header disguised as .pdf)
    spoofed_path = SAMPLES_DIR / "sample_spoofed_invoice.pdf"
    # Write Windows PE 'MZ' magic header but give it a .pdf extension
    spoofed_path.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"A" * 100)
    print(f"[+] Created: {spoofed_path.name}")

    # 3. Double Extension Executable
    double_ext_path = SAMPLES_DIR / "invoice_details.pdf.exe"
    double_ext_path.write_bytes(b"MZ" + os.urandom(500))
    print(f"[+] Created: {double_ext_path.name}")

    # 4. High Entropy Random Byte Sample (Simulates Packed Payload)
    high_entropy_path = SAMPLES_DIR / "sample_packed.exe"
    # Write MZ header followed by completely random high-entropy bytes
    random_bytes = bytes([random.randint(0, 255) for _ in range(4096)])
    high_entropy_path.write_bytes(b"MZ" + random_bytes)
    print(f"[+] Created: {high_entropy_path.name}")

if __name__ == "__main__":
    generate_samples()
    print("\n[+] All synthetic test samples created successfully in src/engine/tests/samples/")