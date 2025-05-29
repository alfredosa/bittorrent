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

    if not tracker_urls and b"announce" not in decoded_data:
        print("No 'announce' or 'announce-list' key found for trackers.")
        if b"url-list" in decoded_data:
            print("Found 'url-list' (Web Seeds):")
            if isinstance(decoded_data[b"url-list"], list):  # Should be a list of URLs
                for web_seed_bytes in decoded_data[b"url-list"]:
                    print(f"  - Web Seed: {web_seed_bytes.decode()}")
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

    args = parser.parse_args()

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
    print(f"Announce URL: {trackers}")


if __name__ == "__main__":
    main()
