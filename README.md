
NFS Packet Analyzer

This Python script processes NFS (Network File System) packets captured in a file and reconstructs data or files transferred over the network. It supports NFS protocol version 4 and extracts useful information such as file names, sizes, and data content.

---

Features

- Extracts and processes NFS packet data (fhandle, offset, size, sequence ID, and more).
- Reconstructs file data from packet fragments using offsets and sizes.
- Saves reconstructed files to disk.
- Provides detailed information about the files and decoded data.
- Verbose mode for debugging and inspecting packet details.

---

Requirements

- Python 3.x
- [Pyshark](https://github.com/KimiNewt/pyshark): A Python wrapper for Tshark.
- Tshark: Installed and properly configured on your system.

---

Installation

1. Clone this repository:
    ```bash
    git clone https://github.com/your_username/nfs-packet-analyzer.git
    cd nfs-packet-analyzer
    ```

2. Install dependencies:
    ```bash
    pip install pyshark
    ```

3. Ensure that Tshark is installed on your system. For example, on Ubuntu:
    ```bash
    sudo apt install tshark
    ```

---

Usage

Run the script with the following command:

```bash
python your_script.py <file_name> [-pv version] [-v]
```

### Arguments

- `<file_name>`: The path to the packet capture file (e.g., `.pcap` or `.pcapng`).
- `-pv version`: (Optional) Specify the NFS protocol version (default: 4). Supported versions: 2, 3, 4.
- `-v`: (Optional) Enable verbose mode for detailed output.

### Example

```bash
python your_script.py capture.pcap -pv 4 -v
```

---

Output

- **Basic Information**: Displays file handles, names, sizes, and decoded data.
- **Reconstructed Files**: Saved to the current directory with their original names or indices (e.g., `0-file_name`).

### Verbose Mode

Provides additional details about:
- Sequence IDs.
- Offsets and counts.
- Read data lengths.

---

Function Overview

- `generate_combinations`: Creates valid combinations of packet fragments based on offsets.
- `load_nfs_packets`: Loads NFS packets from a `.pcap` file.
- `process_packet`: Extracts and processes data from each packet.
- `finalize_files`: Reconstructs and saves files from packet data.
- `display_session_context`: Outputs the reconstructed file information.

---

Known Limitations

- Only supports NFS protocol version 4.
- Decoded data may fail if it contains non-UTF-8 content.
- Large packet captures may require significant memory.

---

Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch:
    ```bash
    git checkout -b feature-branch
    ```
3. Commit your changes:
    ```bash
    git commit -m "Add your message"
    ```
4. Push the branch:
    ```bash
    git push origin feature-branch
    ```
5. Open a pull request.

---

License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

Author

- **Gustave LEGRAND**
- [LinkedIn Profile](https://linkedin.com/in/your-profile) *(Update this with your profile link)*

Feel free to reach out for questions or suggestions!
