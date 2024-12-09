# NFS Packet Capture File Extractor

This Python script processes NFS (Network File System) packets captured in `.pcap` or `.pcapng` files and reconstructs data or files transferred over the network. It supports NFS protocol version 4 and extracts useful information such as file names, sizes, and data content.

## Features

- Extracts and processes NFS packet data (fhandle, offset, size, sequence ID, and more).
- Automatically Reconstructs file data from packet fragments using offsets and sizes.
- Saves reconstructed files
- Provides detailed information about the files and decoded data.
- Verbose mode for inspecting packet details.

## Requirements

- Python 3.x
- [Pyshark](https://github.com/KimiNewt/pyshark): A Python wrapper for Tshark.
- Tshark: Installed and properly configured on your system.

## Installation

1. Clone this repository:
    ```bash
    git clone https://github.com/Magnoir/nfs-packet-capture-file-extractor.git
    cd nfs-packet-capture-file-extractor
    ```
2. Ensure that Tshark is installed on your system. For example, on Ubuntu:
    ```bash
    sudo apt install tshark
    ```

3. Install dependencies:
    ```bash
    pip install pyshark
    ```

## Usage

Run the script with the following command:

```bash
python script.py <file_name> [-pv version] [-v]
```
### Arguments

- `<file_name>`: The path to the packet capture file (e.g., `.pcap` or `.pcapng`).
- `-pv version`: (Optional) Specify the NFS protocol version (default: 4).
- `-v`: (Optional) Enable verbose mode for detailed output.

### Example

```bash
python script.py capture.pcap -v
```

## Output

- **Basic Information**: Displays file handles, names, sizes, and decoded data.
- **Reconstructed Files**: Saved to the current directory with their original names or indices (e.g., `0-file_name`).

### Verbose Mode

Provides additional details about:
- Sequence IDs.
- Offsets and counts.
- Read data lengths.

## Known Limitations

- Only supports NFS protocol version 4.

## Contributing

Contributions are welcome! Please follow these steps:

## Author

- **Magnoir**

Feel free to reach out for questions or suggestions!
