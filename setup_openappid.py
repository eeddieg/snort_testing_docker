from bs4 import BeautifulSoup
import os
import requests
import shutil
import tarfile

# Color palette
class Colors:
  reset = '\033[0m'
  blue = "\033[34m"
  blueBold = "\033[1;34m"
  redBold = '\033[1;31m'
  green = '\033[0;32m'
  greenBold = '\033[1;32m'
  yellow = '\033[0;33m'
  yellowBold = '\033[1;33m'
  red = "\033[31m"
  redBold = "\033[1;31m"

# Configuration
BASE_URL = "https://www.snort.org"
DOWNLOAD_PAGE = "https://www.snort.org/downloads#openappid"
FILENAME = "openappid.tar.gz"
HEADERS = {"User-Agent": "Mozilla/5.0"}
INSTALL_DIR = "openappid"
TEMP_DIR = "tmp"

def running_as_root():
  if not os.getuid() == 0:
    raise PermissionError(f"{Colors.redBold}You need to run this script with sudo or as root.\n {Colors.reset}")

def get_latest_openappid_url():
  print(f"{Colors.yellowBold}[*]{Colors.reset} Fetching the latest OpenAppID package link...")
  response = requests.get(DOWNLOAD_PAGE, headers=HEADERS)
  soup = BeautifulSoup(response.text, 'html.parser')

  for link in soup.find_all('a', href=True):
    href = link.get('href')
    if "openappid" in href:
      tag = link.next_element
      if "tar.gz" in tag: 
        print(f"{Colors.greenBold}[+]{Colors.reset} Found OpenAppID package: {Colors.yellowBold}{href}{Colors.reset}\n")
        return BASE_URL + href

  raise Exception(f"{Colors.redBold}[-]{Colors.reset} Could not find OpenAppID .tar.gz package on Snort.org.")

def createTempFolder():
  tmpdir = os.path.join(os.getcwd(), TEMP_DIR)

  if os.path.exists(tmpdir):
    shutil.rmtree(tmpdir)
  os.makedirs(tmpdir)

  return tmpdir
  
def deleteTempFolder(tmpdir):
  if os.path.exists(tmpdir):
    shutil.rmtree(tmpdir) 

def download_file(url, download_path):
  print(f"{Colors.yellowBold}[*]{Colors.reset} Downloading from {Colors.green}{url}{Colors.reset}...")
  
  tarball_path = os.path.join(download_path, FILENAME)

  with requests.get(url, stream=True) as r:
    r.raise_for_status()
    with open(tarball_path, 'wb') as f:
      for chunk in r.iter_content(chunk_size=8192):
        f.write(chunk)

  print(f"{Colors.greenBold}[+]{Colors.reset} Download complete: {Colors.yellowBold}{download_path}{Colors.reset}\n")

def extract_tarball(download_path, extract_to):
  tar_path = os.path.join(download_path, FILENAME)

  print(f"{Colors.yellowBold}[*]{Colors.reset} Extracting {Colors.green}{tar_path}{Colors.reset} to {Colors.green}{extract_to}{Colors.reset}...")
  
  with tarfile.open(tar_path, "r:gz") as tar:
    tar.extractall(path=extract_to)

    # for member in tar.getmembers():
    #   # Ignore file ownership by resetting uid/gid
    #   member.uid = member.gid = 0
    #   member.uname = member.gname = ""
    #   tar.extract(member, path=extract_to)

  print(f"{Colors.greenBold}[+]{Colors.reset} Extraction complete.\n")

def clear_tempfiles():
  print()

def setup_openappid():
  # running_as_root()

  tmpdir = createTempFolder()
  os.makedirs(INSTALL_DIR, exist_ok=True)

  url = get_latest_openappid_url()
  download_file(url, tmpdir)
  extract_tarball(tmpdir, INSTALL_DIR)

  deleteTempFolder(tmpdir)

  print(f"{Colors.greenBold}[+]{Colors.reset} OpenAppID detectors installed in: {Colors.yellowBold}{INSTALL_DIR}{Colors.reset}")

if __name__ == "__main__":
  try:
    setup_openappid()
  except Exception as e:
    print(f"[ERROR] {e}")
