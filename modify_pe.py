import sys
import pefile
import struct

def add_resource(pe, data, type_id, id, language=0x0409):  # 0x0409 is English (United States)
    # Ensure the resource directory exists
    if pe.DIRECTORY_ENTRY_RESOURCE is None:
        pe.DIRECTORY_ENTRY_RESOURCE = pefile.DIRECTORY_ENTRY(['IMAGE_DIRECTORY_ENTRY_RESOURCE'])
        pe.DIRECTORY_ENTRY_RESOURCE.struct = pefile.RESOURCE_DIRECTORY()
        pe.DIRECTORY_ENTRY_RESOURCE.struct.NumberOfNamedEntries = 0
        pe.DIRECTORY_ENTRY_RESOURCE.struct.NumberOfIdEntries = 0
        pe.DIRECTORY_ENTRY_RESOURCE.pointer_to_raw_data = len(pe.write())
        pe.DIRECTORY_ENTRY_RESOURCE.size = pefile.RESOURCE_DIRECTORY().size

    resource_dir = pe.DIRECTORY_ENTRY_RESOURCE.struct

    # Create a new resource entry
    resource_entry = pefile.RESOURCE_ENTRY()
    resource_entry.id = id
    resource_entry.offset_to_data = 0
    resource_entry.data.is_directory = False
    resource_entry.data.language = language
    resource_entry.data.offset_to_data = len(pe.write())  # Placeholder for the actual offset

    # Add the new resource entry to the resource directory
    resource_dir.entries.append(resource_entry)

    # Update the resource directory size
    resource_dir.size += pefile.RESOURCE_ENTRY.size

    # Write the resource data to the end of the file
    pe.write(data, offset=resource_dir.entries[-1].offset_to_data)

    # Update the resource entry offset to data
    resource_dir.entries[-1].offset_to_data = pe.get_offset_from_rva(resource_dir.entries[-1].offset_to_data)

    return pe

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
    pe = add_resource(pe, embedded_data, pefile.RESOURCE_TYPE['RT_RCDATA'], 1033)

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
