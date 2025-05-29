import os
import bencodepy
import argparse
import hashlib


def decode(torrent_file):
    with open(torrent_file, "rb") as file:
        t_bytes = file.read()

    return bencodepy.decode(t_bytes)


def get_info_hash(info_dict):
    encoded_info = bencodepy.encode(info_dict)
    return hashlib.sha1(encoded_info).digest()


def get_tracker_urls(decoded_data):
    """
    Extracts tracker URLs from decoded torrent data.
    Prioritizes 'announce', then 'announce-list'.
    Returns a list of tracker URLs.
    """
    tracker_urls = []
    if b"announce" in decoded_data:
        url = decoded_data[b"announce"].decode()
        if url:
            tracker_urls.append(url)
            print(f"Found 'announce' URL: {url}")

    if b"announce-list" in decoded_data:
        print("Found 'announce-list':")
        for tier in decoded_data[b"announce-list"]:
            for tracker_bytes in tier:
                url = tracker_bytes.decode()
                if url not in tracker_urls:
                    tracker_urls.append(url)
                print(f"  - {url}")

    # a webseed is an HTTP or FTP server that hosts the entire file being downloaded
    # vs a seed which essentially is a peer that has downloaded and is actively sharing
    # the file
    if not tracker_urls and b"announce" not in decoded_data:
        print("No 'announce' or 'announce-list' key found for trackers.")
        if b"url-list" in decoded_data:
            if isinstance(decoded_data[b"url-list"], list):  # Should be a list of URLs
                urls = decoded_data[b"url-list"]
                print(f"Found 'url-list' (Web Seeds): {len(urls)}")
                # I don't know if we need to add them to the announce...
                # for web_seed_bytes in urls:
                # ----tracker_urls.append(web_seed_bytes.decode())
            else:  # BEP 19 also allows a single string if only one web seed
                print(f"  - Web Seed: {decoded_data[b'url-list'].decode()}")

    return tracker_urls


def main():
    parser = argparse.ArgumentParser(
        description="AlfieTorrent: A simple BitTorrent client."
    )
    parser.add_argument("torrent_file", help="Path to the .torrent file")
    parser.add_argument(
        "-o", "--output", help="Path to save the downloaded content", default="."
    )
    parser.add_argument(
        "-pt", "--print-trackers", help="print the trackers of the file", default=False
    )

    args = parser.parse_args()
    print(args)

    if not os.path.exists(args.torrent_file):
        print(f"{args.torrent_file} does not exist")
        exit(1)

    decoded_data = {}
    try:
        decoded_data = decode(args.torrent_file)
    except Exception as e:
        print(f"error decoding torrent file: {e}")

    info = decoded_data.get(b"info")
    if not info:
        print("torrent does not contain anything to download")
        exit(1)

    # could be a way to potentially prompt the user for a seeder?? 🐘
    trackers = get_tracker_urls(decoded_data)
    if args.print_trackers:
        print(f"Trackers {trackers}")

    seed_download = False
    if trackers:
        seed_download = True

    print("\n--- Info Dictionary Details ---")
    name = info.get(b"name")
    if name:
        print(f"Name: {name.decode()}")

    piece_length = info.get(b"piece length")
    if piece_length is not None:
        print(f"Piece Length: {piece_length} bytes")

    pieces_hashes_concat = info.get(b"pieces")
    if pieces_hashes_concat:
        num_hashes = len(pieces_hashes_concat) // 20
        print(f"Number of pieces: {num_hashes}")

    if b"length" in info:
        total_length = info.get(b"length")
        print(f"File Length (Single File): {total_length} bytes")
    elif b"files" in info:
        print("Files (Multi-file torrent):")
        files_list = info.get(b"files")
        total_length = 0
        for i, file_info in enumerate(files_list):
            file_path_list = file_info.get(b"path", [])
            file_len = file_info.get(b"length")
            readable_path = os.path.join(*(p.decode() for p in file_path_list))
            print(f"  - File {i+1}: Path: {readable_path}, Length: {file_len} bytes")
            if file_len:
                total_length += file_len
        print(f"Total Length (Multi-file): {total_length} bytes")

    info_hash_bytes = get_info_hash(info)
    print("\n--- Info Hash ---")
    print(f"Info Hash (hexadecimal): {info_hash_bytes.hex()}")


if __name__ == "__main__":
    main()
