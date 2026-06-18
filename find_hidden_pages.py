import requests
import concurrent.futures
import argparse
import csv
from tqdm import tqdm
from urllib.parse import urlparse

def load_paths(wordlist_file):
    with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as file:
        return [line.strip() for line in file if line.strip()]

def check_path(args):
    path, base_url, headers, timeout = args
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        print(f"TESTAR: {url} → {r.status_code}")
        if r.status_code == 200:
            return (url, r.status_code, len(r.text))
    except Exception as e:
        print(f"ERROR: {url} → {e}")
    return None

def main():
    parser = argparse.ArgumentParser(description="Hidden page finder, utan 404-filtrering.")
    parser.add_argument("--url", required=True, help="Base URL to scan (e.g. https://example.com)")
    parser.add_argument("--wordlist", required=True, help="Path to wordlist file")
    parser.add_argument("--output", default="resultat.csv", help="CSV file for results")
    parser.add_argument("--threads", type=int, default=20, help="Number of parallel threads")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout for requests")
    args = parser.parse_args()

    parsed_url = urlparse(args.url)
    domain = parsed_url.netloc.replace('.', '_')
    output_filename = args.output if args.output != "resultat.csv" else f"doldasidor_{domain}.csv"

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; HiddenPageFinder/2.1)"
    }

    print(f"\nLetar efter dolda sidor på: {args.url}")
    print(f"Ordlistefil: {args.wordlist}\n")

    paths = load_paths(args.wordlist)
    found = []

    work_args = [(path, args.url, headers, args.timeout) for path in paths]

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        results = list(tqdm(executor.map(check_path, work_args), total=len(paths), desc="Scanning"))

    for result in results:
        if result:
            url, code, length = result
            print(f"[HITTAD] {url} (Status: {code}, Längd: {length})")
            found.append((url, code, length))

    # Spara resultat
    if found:
        with open(output_filename, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["URL", "Status", "Length"])
            for url, code, length in found:
                writer.writerow([url, code, length])
        print(f"\nSökning klar! Hittade sidor sparade i {output_filename}")
    else:
        print("Inga dolda sidor hittades.")

if __name__ == "__main__":
    main()
