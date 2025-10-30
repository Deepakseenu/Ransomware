import os
import time

target_folder = "/home/yashu/Downloads/test_activity"

# Create some fake files to "encrypt"
for i in range(5):
    with open(os.path.join(target_folder, f"doc_{i}.txt"), "w") as f:
        f.write("This is a safe test file.")

print("[+] Fake ransomware starting encryption simulation...")

for file in os.listdir(target_folder):
    path = os.path.join(target_folder, file)
    if os.path.isfile(path):
        new_name = path + ".locked"
        os.rename(path, new_name)
        print(f"[*] Renamed {file} -> {new_name}")
        time.sleep(1)

print("[+] Encryption simulation complete.")
