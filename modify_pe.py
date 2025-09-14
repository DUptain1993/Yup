import sys
import pefile

def embed_executable(target_exe, embedded_exe):
    # Read the target executable
    with open(target_exe, 'rb') as f:
        target_data = f.read()

    # Create a PE object
    pe = pefile.PE(data=target_data)

    # Read the embedded executable
    with open(embedded_exe, 'rb') as f:
        embedded_data = f.read()

    # Add the embedded executable as a resource
    pe.add_resource_data(pe.RESOURCE_TYPE['RT_RCDATA'], 1033, embedded_data)

    # Write the modified PE data back to a new file
    modified_exe = target_exe.replace('.exe', '_modified.exe')
    with open(modified_exe, 'wb') as f:
        f.write(pe.write())

    return modified_exe

def modify_entry_point(modified_exe):
    # Read the modified executable
    with open(modified_exe, 'rb') as f:
        modified_data = f.read()

    # Create a PE object
    pe = pefile.PE(data=modified_data)

    # Adjust the entry point
    original_entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    new_entry_point = original_entry_point + 0x10  # Adjust the offset as needed
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_entry_point

    # Write the modified PE data back to a new file
    final_exe = modified_exe.replace('_modified.exe', '_final.exe')
    with open(final_exe, 'wb') as f:
        f.write(pe.write())

    return final_exe

if __name__ == "__main__":
    target_exe = sys.argv[1]
    embedded_exe = sys.argv[2]

    modified_exe = embed_executable(target_exe, embedded_exe)
    final_exe = modify_entry_point(modified_exe)

    print(f"Final executable: {final_exe}")
