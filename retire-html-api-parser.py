import sys
import re
import requests
from bs4 import BeautifulSoup

def get_vulnerability_link_and_count(library, version):
    query = f"site:snyk.io {library} (version: {version}) vulnerabilities"
    url = "https://www.googleapis.com/customsearch/v1"

    params = {
        "q": query,
        "key": "<YOUR_API_KEY>",
        "cx": "<SEARCH_ENGINE_ID>"
    }

    response = requests.get(url, params=params)
    data = response.json()

    # Get the first result link
    snyk_link = None
    if data.get('items'):
        snyk_link = data['items'][0]['link']

    # If a Snyk link is found, retrieve the vulnerability count and highest severity
    vulnerability_count = None
    highest_severity = None
    if snyk_link:
        snyk_page = requests.get(snyk_link)
        soup = BeautifulSoup(snyk_page.text, 'html.parser')

        # Find the vulnerability table body
        vuln_table_body = soup.find('tbody', {'class': 'vue--table__tbody'})

        if vuln_table_body:
            # Count the number of rows in the table body
            vulnerability_count = len(vuln_table_body.find_all('tr'))

            # Define the severity order
            severity_order = ['low', 'medium', 'high']

            for row in vuln_table_body.find_all('tr'):
                # Find the severity list in the row
                severity_list = row.find('ul', {'class': 'vue--severity'})

                if severity_list:
                    # Find all severity items in the list
                    severity_items = severity_list.find_all('li')

                    for item in severity_items:
                        # Determine the severity of the item
                        item_severity = None
                        for severity in severity_order:
                            if 'vue--severity__item--' + severity in item.get('class', []):
                                item_severity = severity
                                break

                        # If the item's severity is higher than the highest found so far, update the highest severity
                        if highest_severity is None or severity_order.index(item_severity) > severity_order.index(highest_severity):
                            highest_severity = item_severity

    return snyk_link, vulnerability_count, highest_severity

def parse_file(file_path):
    try:
        with open(file_path, 'r') as file:
            contents = file.read()
    except FileNotFoundError:
        print(f"The file {file_path} does not exist.")
        sys.exit(1)

    soup = BeautifulSoup(contents, 'html.parser')

    # Find the table with id 'results'
    results_table = soup.find('table', {'id': 'results'})

    if not results_table:
        raise ValueError('No table with id "results" found')

    # Find all rows in the table with the class 'vulnerable'
    rows = results_table.find_all('tr', {'class': 'vulnerable'})

    if not rows:
        print("No vulnerable technologies found in the HTML file.")
        sys.exit(0)

    for row in rows:
        cells = row.find_all('td')

        if len(cells) < 3:
            continue

        # The first cell contains the library name
        library = cells[0].get_text(strip=True)

        # The second cell contains the library version
        version = cells[1].get_text(strip=True)

        # The third cell contains the location, but we need to exclude the vulnerability info
        location = cells[2].find(string=True, recursive=False).strip()

        # Use regular expression to find and replace underscores before "Vulnerability info:"
        location = re.sub(r'_+Vulnerability info:', '', location)

        print(f'\nLibrary Version: {library}@{version}')
        print(f'{location}')

        snyk_link, vulnerability_count, highest_severity = get_vulnerability_link_and_count(library, version)
        if vulnerability_count is not None:
            print(f'Vulnerability Count: {vulnerability_count}')
        if highest_severity is not None:
            print(f'Highest Severity: {highest_severity.capitalize()}')
        if snyk_link:
            print(f'Vulnerability Details: {snyk_link}')

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python retire_parser.py <filename>")
        sys.exit(1)

    file_path = sys.argv[1]
    parse_file(file_path)
