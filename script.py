import pyshark
import sys, os

def generate_combinations(packet_sizes, slicing):
    # Result list to store all valid combinations
    result = []
    # Recursive function to generate all combinations
    def helper(index, current_combination, current_sum, remaining_slicing):
        # If the current sum matches the target slicing, add the combination to the result
        if current_sum == remaining_slicing[-1]:
            result.append(current_combination)
            return
        # Stop if we have processed all packets
        if index == len(packet_sizes):
            return
        # Iterate over packet sizes to find valid combinations
        for i in range(index, len(packet_sizes)):
            packet_size, data = packet_sizes[i]
            packet_size = int(packet_size)
            # If adding the current packet matches the slicing target, proceed recursively
            if current_sum + packet_size == remaining_slicing[len(current_combination)]:
                helper(i, current_combination + [(packet_size, data)], current_sum + packet_size, remaining_slicing)
    # Start recursion with the first packet
    helper(0, [], 0, slicing)
    return result

# Load NFS packets from a file
def load_nfs_packets(file_path, filter='nfs'):
    return [packet for packet in pyshark.FileCapture(file_path, display_filter=filter)]

# Extract NFS data from a packet
def get_nfs_data(packet):
    return getattr(packet, 'nfs', None) if hasattr(packet, 'nfs') else None

# Extract relevant fields from NFS data
def extract_nfs_fields(nfs_data):
    return (
        getattr(nfs_data, 'fhandle', None).replace(":", "") if hasattr(nfs_data, 'fhandle') else None,
        getattr(nfs_data, 'offset4', None),
        getattr(nfs_data, 'count4', None),
        getattr(nfs_data, 'entry_name', None),
        getattr(nfs_data, 'fattr4_size', None),
        getattr(nfs_data, 'seqid', None),
        getattr(nfs_data, 'data', None).replace(":", "") if hasattr(nfs_data, 'data') else None,
        getattr(nfs_data, 'read_data_length', None)
    )

# Process a packet and update the session context
def process_packet(packet, session_context):
    # Extract NFS data from the packet
    nfs_data = get_nfs_data(packet)
    if not nfs_data:
        return session_context

    # Extract relevant fields from the NFS data
    handle, ofs, count, name, size, seqid, data, read_data_length = extract_nfs_fields(nfs_data)

    # Initialize session context if it doesn't exist
    if handle and handle not in session_context:
        initialize_session_context(session_context, handle)

    # Update session context with name and size
    update_session_context_with_name_and_size(session_context, handle, name, size)

    # Update session context with seqid
    update_session_context_with_seqid(session_context, handle, seqid, ofs, count)

    # Update session context with data
    update_session_context_with_data(session_context, seqid, data, read_data_length)

    return session_context

# Initialize the session context for a given file handle
def initialize_session_context(session_context, handle):
    session_context[handle] = { "name": "", "size": "", 'stateid': [], 'seqid': {}, 'decoded_data': "" }

# Update session context with file name and size
def update_session_context_with_name_and_size(session_context, handle, name, size):
    if name and size and handle:
        session_context[handle]['name'] = name
        session_context[handle]['size'] = size
    if size and handle:
        session_context[handle]['size'] = size

# Update session context with sequence ID details
def update_session_context_with_seqid(session_context, handle, seqid, ofs, count):
    if seqid and handle and ofs and count:
        session_context[handle]['seqid'][seqid] = { "ofs": ofs, "count": count, "data": "", "read_data_length": None }

# Update session context with data from the packet
def update_session_context_with_data(session_context, seqid, data, read_data_length):
    if data and seqid:
        for elt in session_context:
            if seqid in session_context[elt]["seqid"]:
                session_context[elt]["seqid"][seqid]["data"] = bytes.fromhex(data)
                session_context[elt]["seqid"][seqid]["read_data_length"] = read_data_length
                break

# Decode raw data and save the file
def finalize_files(session_context, handle):
    # Return if no sequence IDs exist
    if session_context[handle]["seqid"] == {}:
        return session_context
    
    # Decode raw data if size is not specified
    raw_data = b"".join(session_context[handle]["seqid"][seqid]["data"] for seqid in session_context[handle]["seqid"])
    try:
        session_context[handle]["decoded_data"] = bytes.decode(raw_data)
    except UnicodeDecodeError:
        # Reconstruct file data based on offsets and save to disk
        offset = []
        for seqid in session_context[handle]["seqid"]:
            offset.append(int(session_context[handle]["seqid"][seqid]["ofs"]))
        
        offset.append(int(session_context[handle]["size"]))
        offset = offset[1:]

        raw_data_packets = []
        for seqid in session_context[handle]["seqid"]:
            raw_data_packets.append((session_context[handle]["seqid"][seqid]["read_data_length"], session_context[handle]["seqid"][seqid]["data"]))

        combinations = generate_combinations(raw_data_packets, offset)

        for idx, comb in enumerate(combinations):
            raw_data = b"".join(pkt[1] for pkt in comb)
            name_decoded = session_context[handle]["name"]
            if not os.path.exists(f"{idx}-{name_decoded}"):
                with open(f"{idx}-{name_decoded}", "wb") as f:
                    f.write(raw_data)
                print(f"File saved as {idx}-{name_decoded}")
            else:
                print(f"File {idx}-{name_decoded} already exists, skipping.")
            session_context[handle]["decoded_data"] += name_decoded + " , "
    return session_context
    
def main():
    # Parse command line arguments
    file_path, protocol_version, verbose = parse_arguments()
    if protocol_version != 4:
        print(f"NFS protocol version {protocol_version} not implemented.")
        return
    
    # Process NFS packets for version 4
    if protocol_version == 4:
        process_nfs_packets(file_path, verbose)

# Parse command line arguments
def parse_arguments():
    if len(sys.argv) < 2:
        print("Usage: python your_script.py <file_name> [-pv version] [-v]")
        sys.exit(1)

    file_path = sys.argv[1]
    protocol_version = 4
    verbose = False

    if '-pv' in sys.argv:
        pv_index = sys.argv.index('-pv')
        if pv_index + 1 < len(sys.argv) and sys.argv[pv_index + 1] in ['2', '3', '4']:
            protocol_version = int(sys.argv[pv_index + 1])
        else:
            print("Usage: python your_script.py <file_name> [-pv version] [-v]")
            print("Available versions: 4 (default: 4) (other versions are not implemented)")
            sys.exit(1)

    if '-v' in sys.argv:
        verbose = True

    return file_path, protocol_version, verbose

# Process NFS packets
def process_nfs_packets(file_path, verbose):
    global nfs_packets
    nfs_packets = load_nfs_packets(file_path)

    session_context = {}

    print("Processing packets...")
    for _, pkt in enumerate(nfs_packets):
        session_context = process_packet(pkt, session_context)
    
    for handle in session_context:
        session_context = finalize_files(session_context, handle)

    print("Processing complete.")
    display_session_context(session_context, verbose)
        

# Display session context
def display_session_context(session_context, verbose):
    print("Files or information found in the NFS packets:")
    for handle, context in session_context.items():
        display_basic_info(handle, context)
        if verbose:
            display_verbose_info(context['seqid'])
        if context['decoded_data'] or context['name']: 
            print("-----------------------------")

# Display basic information about the file
def display_basic_info(handle, context):
    name = context['name']
    decoded_data = context['decoded_data']
    if not name and decoded_data:
        print(f"File handle (file ID): {handle}")
        print(f"Decoded data:\n{decoded_data}".rstrip())
        print(f"Size: {context['size']} bytes")
    elif name:
        print(f"File handle (file ID): {handle}")
        print(f"File name: {name}")
        print(f"File(s): {decoded_data if decoded_data else 'No data found.   '}"[:-3])
        print(f"Size: {context['size']} bytes")

# Display verbose information about seqids
def display_verbose_info(seqid_info):
    seqids = list(seqid_info.keys())
    offset = [seqid_info[seqid]["ofs"] for seqid in seqid_info]
    count = [seqid_info[seqid]["count"] for seqid in seqid_info]
    read_data_length = [seqid_info[seqid]["read_data_length"] for seqid in seqid_info]
    if len(seqids) > 0:
        print(f"Seqids: {seqids}")
        print(f"Offset: {offset}")
        print(f"Count: {count}")
        print(f"Read data length: {read_data_length}")

# Entry point
if __name__ == '__main__':
    main()
