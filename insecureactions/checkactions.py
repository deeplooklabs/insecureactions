import requests
import base64
import os
import sys
import logging
import re
from colorama import init, Fore

init(autoreset=True)

class CustomFormatter(logging.Formatter):
    """ Custom logging formatter with color """

    # Definindo as cores para cada nível de log
    format_dict = {
        logging.DEBUG: Fore.CYAN + "%(asctime)s - %(levelname)s - %(message)s" + Fore.RESET,
        logging.INFO: Fore.GREEN + "%(asctime)s - %(levelname)s - %(message)s" + Fore.RESET,
        logging.WARNING: Fore.YELLOW + "%(asctime)s - %(levelname)s - %(message)s" + Fore.RESET,
        logging.ERROR: Fore.RED + "%(asctime)s - %(levelname)s - %(message)s" + Fore.RESET,
        logging.CRITICAL: Fore.RED + "%(asctime)s - %(levelname)s - %(message)s" + Fore.RESET
    }

    def format(self, record):
        log_fmt = self.format_dict.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

for handler in logger.handlers:
    handler.setFormatter(CustomFormatter())

try:
    GITHUB_TOKEN = os.getenv('GITHUB_ACCESS_TOKEN')
except:
    logging.error('Not set GITHUB_ACCESS_TOKEN enviroment!')

DANGEROUS_INPUTS = {
    'pull-request': 'github.event.pull_request',
    'comments': 'github.event.comment.body',
    'issues-body': 'github.event.issue.body',
    'issues-title': 'github.event.issue.title',
    'head_ref': 'github.head_ref',
    'authors-name': 'authors.name',
    'authors-email': 'authors.email',
    'events': 'github.event.inputs.',
    'general-events': 'github.event',
    # Add more potentially dangerous patterns here
    'exec': 'exec',
    'run': 'run',
    'bash': 'bash',
    'shell': 'shell'
}
LINK_REGEX = r'https?://[^\s]+'

def make_request(url, params=None, method='get'):
    headers = {'Authorization': f'token {GITHUB_TOKEN}'}
    try:
        if method == 'get':
            response = requests.get(url, params=params, headers=headers)
        else:
            response = requests.head(url, headers=headers)
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        return None

def find_links_in_text(text):
    return re.findall(LINK_REGEX, text)

def check_link_validity(link):
    response = make_request(link, method='head')
    if response and response.status_code == 200:
        return True
    return False

def find_and_check_links(org_name, repo_name, file_path):
    url = f"https://api.github.com/repos/{org_name}/{repo_name}/contents/{file_path}"
    response = make_request(url)

    if response and response.status_code == 200:
        content = response.json().get('content', '')
        decoded_content = base64.b64decode(content).decode('utf-8')

        links = find_links_in_text(decoded_content)
        for link in links:
            if not check_link_validity(link):
                logging.warning(f"Broken link hijacking risk: {link} in {file_path}")

def get_all_repositories(org_name):
    url = f"https://api.github.com/orgs/{org_name}/repos?per_page=100"
    repositories = []
    page = 1

    while True:
        response = make_request(url, params={'page': page})
        if response and response.status_code == 200:
            page_repositories = response.json()
            if not page_repositories:
                break
            repositories.extend(page_repositories)
            page += 1
        else:
            break

    return repositories

def check_directory_in_repo(org_name, repo_name, directory):
    url = f"https://api.github.com/repos/{org_name}/{repo_name}/contents/{directory}"
    response = make_request(url)

    if response and response.status_code == 200:
        return True
    return False

def search_input_in_workflow_content(org_name, repo_name, file_path, input_tag):
    url = f"https://api.github.com/repos/{org_name}/{repo_name}/contents/{file_path}"
    response = make_request(url)

    if response and response.status_code == 200:
        content = response.json().get('content', '')
        decoded_content = base64.b64decode(content).decode('utf-8')

        return input_tag in decoded_content.lower()
    return False

def check(org_name):

    repositories = get_all_repositories(org_name)

    if not repositories:
        logging.info(f"No repositories found for {org_name}. Exiting.")
        return

    total_repositories = len(repositories)
    logging.info(f"Total repositories in {org_name}: {total_repositories}")

    for repo in repositories:
        repo_name = repo["name"]

        github_directory_exists = check_directory_in_repo(org_name, repo_name, ".github")
        if github_directory_exists:

            workflows_directory_exists = check_directory_in_repo(org_name, repo_name, ".github/workflows")
            if workflows_directory_exists:

                workflows_url = f"https://api.github.com/repos/{org_name}/{repo_name}/contents/.github/workflows"
                workflows_response = make_request(workflows_url)
                if workflows_response and workflows_response.status_code == 200:
                    workflow_files = workflows_response.json()
                    for workflow_file in workflow_files:
                        file_path = workflow_file.get('path', '')

                        find_and_check_links(org_name, repo_name, file_path)

                        for input_tag in DANGEROUS_INPUTS.values():
                            if search_input_in_workflow_content(org_name, repo_name, file_path, input_tag):
                                logging.warning(f"Potential security issue in {repo_name}: '{input_tag}' found in {file_path}")