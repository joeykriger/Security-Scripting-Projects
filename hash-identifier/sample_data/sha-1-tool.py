import subprocess
import time
from pathlib import Path

path = Path("sample_data/pwnedpasswords_sha1_sample_small.txt")

count = 0
sha1_count = 0
start = time.time()

for raw in path.read_text(encoding="utf-8").splitlines()[:100]:
    if not raw.strip():
        continue
    suffix = raw.split(":", 1)[0]
    hash_value = "00000" + suffix
    result = subprocess.run(
        ["just", "run", "--", hash_value],
        capture_output=True,
        text=True,
    )
    count += 1
    if "SHA-1" in result.stdout:
        sha1_count += 1

elapsed = time.time() - start
throughput = count / elapsed if elapsed > 0 else 0.0

print(f"processed {count} hashes")
print(f"sha1_count {sha1_count}")
print(f"elapsed {elapsed:.2f}s")
print(f"throughput {throughput:.2f} hashes/s")

