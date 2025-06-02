import sys
import os
import argparse
import hashlib
import random
import requests

import bencodepy


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
    return tracker_urls


def get_web_seeds(decoded_data):
    web_seeds = []
    # a webseed is an HTTP or FTP server that hosts the entire file being downloaded
    # vs a seed which essentially is a peer that has downloaded and is actively sharing
    # the file
    if not web_seeds and b"announce" not in decoded_data:
        print("No 'announce' or 'announce-list' key found for trackers.")
        if b"url-list" in decoded_data:
            if isinstance(decoded_data[b"url-list"], list):  # Should be a list of URLs
                urls = decoded_data[b"url-list"]
                print(f"Found 'url-list' (Web Seeds): {len(urls)}")

                # I don't know if we need to add them to the announce...
                for web_seed_bytes in urls:
                    web_seeds.append(web_seed_bytes.decode())
            else:  # BEP 19 also allows a single string if only one web seed
                print(f"  - Web Seed: {decoded_data[b'url-list'].decode()}")

    return web_seeds


def random_urls_from_list(urls, num=5):
    if len(urls) <= num:
        return urls
    return random.sample(urls, num)


def verify_piece_hash(piece_data, piece_hash):
    piece_hash_bytes = hashlib.sha1(piece_data).digest()  # apples to apples
    return piece_hash_bytes == piece_hash


def main():
    parser = argparse.ArgumentParser(
        description="AlfieTorrent: A simple BitTorrent client."
    )
    parser.add_argument(
        "torrent_file",
        help="Path to the .torrent file",
        type=str,
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Path to save the downloaded content",
        type=str,
        default=".",
    )
    parser.add_argument(
        "-pt",
        "--print-trackers",
        help="print the trackers of the file",
        type=bool,
        default=False,
    )
    parser.add_argument(
        "-sm",
        "--seeders-max",
        help="Maximum number of seeders to connect to",
        type=int,
        default=5,
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
        sys.exit(1)

    # could be a way to potentially prompt the user for a seeder?? 🐘
    trackers = get_tracker_urls(decoded_data)
    if args.print_trackers:
        print(f"Trackers {trackers}")

    # this might be an incorrect assumption actually⁉
    seed_download = False
    if trackers:
        seed_download = True
    else:
        w_seeds = get_web_seeds(decoded_data)
        if w_seeds:
            print(
                "pulling data from web_seeds (like): \n"
                + ", ".join(random_urls_from_list(w_seeds, 5)),
            )
        else:
            print("No trackers or web seeds found. Cannot download.")
            sys.exit(1)

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

    num_files = 0
    if b"length" in info:
        total_length = info.get(b"length")
        num_files = 1
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
                num_files += 1
        print(f"Total Length (Multi-file): {total_length} bytes")

    info_hash_bytes = get_info_hash(info)
    print("\n--- Info Hash ---")
    print(f"Info Hash (hexadecimal): {info_hash_bytes.hex()}")

    # The last piece might be shorter than the others hehe
    last_piece_length = total_length - (piece_length * (num_hashes - 1))

    # gotta love python lol
    list_of_pieces = [False] * num_hashes

    if seed_download:
        print("we are not supporting this right now")
        return

    downloaded = True
    file_handle = create_file_and_get_handle(args.output, name.decode(), total_length)

    for i, _ in enumerate(list_of_pieces):
        target_url = (
            f"{random_urls_from_list(w_seeds, 1)[0].rstrip('/')}/{name.decode()}"
        )
        start_byte = i * piece_length
        current_piece_actual_length = piece_length
        if i == num_hashes - 1:
            current_piece_actual_length = last_piece_length

        range_end_byte = start_byte + current_piece_actual_length - 1
        headers = {"Range": f"bytes={start_byte}-{range_end_byte}"}

        try:
            response = requests.get(
                target_url, headers=headers, stream=True, timeout=10
            )  # Added stream and timeout? I guess?
            response.raise_for_status()  # this is nice

            piece_data = b""
            for chunk in response.iter_content(chunk_size=8192):  # Download in chunks
                piece_data += chunk

            # Basic checkkkkk
            expected_length = (range_end_byte - start_byte) + 1
            if (
                len(piece_data) != expected_length
            ):  # expected_download_size from corrected range
                print(f"Error: Downloaded size mismatch for piece {i+1}.")
                downloaded = False
                break

            if verify_piece_hash(
                piece_data, pieces_hashes_concat[i * 20 : (i + 1) * 20]
            ):
                print(f"Piece {i+1} hash verified.")
                # Write piece_data to output_file_handle at start_byte (as per memory improvement)
                try:
                    save_to_file(file_handle, piece_data, i, start_byte)
                    list_of_pieces[i] = True
                except IOError as e:
                    print(f"Error writing piece {i+1} to file: {e}")
                    downloaded = False
                    break
            else:
                print(f"Piece {i+1} hash verification FAILED.")
                downloaded = False
                break

            progress_percent = (sum(1 for p in list_of_pieces if p) * 100) / num_hashes
            print(f"Progress: {progress_percent:.2f}% completed.", end="\r")

        except requests.exceptions.RequestException as e:
            print(f"Error downloading piece {i + 1}: {e}")
            downloaded = False
            break

    if not downloaded:
        print("Download failed. Exiting.")
        return


def create_file_and_get_handle(output_path, filename, total_file_length):
    if not os.path.exists(output_path):
        os.makedirs(output_path)

    if output_path == ".":
        output_path = os.getcwd()
    full_path = os.path.join(output_path, filename)

    # Opening a file in wb mode truncates it if it exists.
    with open(full_path, "wb") as f:
        f.seek(total_file_length - 1)
        f.write(b"\0")

    # read-write binary mode
    return open(full_path, "r+b")


def save_to_file(output_file_handle, piece_data, i, start_byte):
    try:
        output_file_handle.seek(start_byte)  # start_byte for current piece
        output_file_handle.write(piece_data)
    except IOError as e:
        print(f"Error writing piece {i+1} to file: {e}")


if __name__ == "__main__":
    main()
