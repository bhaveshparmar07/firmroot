import os

rom_path = r"C:\Users\Bhavesh\.gemini\antigravity\brain\979e7942-44e9-49f5-8d5a-4f19bea2f7af\scratch\firmroot\uploads\FR-1795153032_EDS5000_2.1.0.0R3.rom"
size = os.path.getsize(rom_path)
print(f"Searching in ROM ({size} bytes)...")

term = b"dsrcts"
with open(rom_path, "rb") as f:
    chunk_size = 1024 * 1024 * 4
    offset = 0
    while True:
        data = f.read(chunk_size)
        if not data:
            break
        idx = data.lower().find(term)
        if idx != -1:
            found_offset = offset + idx
            print(f"FOUND '{term.decode()}' at byte offset: {found_offset} (hex: {hex(found_offset)})")
            f.seek(max(0, found_offset - 30))
            context = f.read(100)
            print("Context:", context)
            break
        offset += len(data) - len(term)
        f.seek(offset)
    else:
        print(f"Term '{term.decode()}' NOT found in raw ROM.")
