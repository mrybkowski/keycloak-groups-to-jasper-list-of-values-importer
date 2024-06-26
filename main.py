import requests
import hashlib
import time

KEYCLOAK_USERNAME = 'admin'
KEYCLOAK_PASSWORD = 'admin'
KEYCLOAK_REALM_NAME = 'tef'
JASPER_PASSWORD = 'jasperadmin'
JASPER_USERNAME = 'jasperadmin'
KEYCLOAK_BASE_URL = 'http://ems2tstkl.servis.justice.cz'
JASPER_SERVER_API_URL = 'http://ems2tstjasper.servis.justice.cz/jasperserver/rest_v2'
JASPER_RESOURCE_ID = 'GroupList'
JASPER_SUBFOLDER_PATH = 'EM/Lists'

def get_keycloak_token():
    keycloak_url = f'{KEYCLOAK_BASE_URL}/realms/master/protocol/openid-connect/token'
    token_endpoint = keycloak_url.format(realm_name=KEYCLOAK_REALM_NAME)

    payload = {
        'grant_type': 'password',
        'username': KEYCLOAK_USERNAME,
        'password': KEYCLOAK_PASSWORD,
        'client_id': 'admin-cli'
    }

    try:
        response = requests.post(token_endpoint, data=payload, verify=False)
        token = response.json().get('access_token')
        return token
    except requests.exceptions.RequestException as e:
        print('KeyCloack: Failed to obtain Bearer token:', str(e))
        return None
    
import requests

def get_jasperserver_token():
    payload = {
        'j_username': JASPER_USERNAME,
        'j_password': JASPER_PASSWORD
    }

    try:
        response = requests.post(JASPER_SERVER_API_URL + '/login', data=payload)
        response.raise_for_status()
        token = response.cookies.get('JSESSIONID')
        
        if token:
            return token
        else:
            print('JasperServer: Token not found in response cookies')
            return None

    except requests.exceptions.RequestException as e:
        print(f'JasperServer: Error during HTTP request: {e}')
        return None


def get_keycloak_groups(token):
    groups_endpoint = f'{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/groups'
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
    }

    try:
        response = requests.get(groups_endpoint, headers=headers, verify=False)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print('KeyCloak: Failed to fetch groups:', str(e))

def update_jasper_group_list(session_id, groups):
    jasperserver_endpoint = f'{JASPER_SERVER_API_URL}/resources/{JASPER_SUBFOLDER_PATH}/{JASPER_RESOURCE_ID}'
    headers = {
        'Cookie': f'JSESSIONID={session_id}',
        'Content-Type': 'application/repository.listofvalues+json',
        'Accept': 'application/json',
    }

    def extract_items(groups):
        items = []
        for group in groups:
            items.append({
                "label": group['path'],
                "value": group['path']
            })
            if group.get('subGroups'):
                items.extend(extract_items(group['subGroups']))
        return items
    
    response = requests.get(jasperserver_endpoint, headers=headers)
    if response.status_code == 200:
        existing_data = response.json()
    else:
        print(f'JasperServer: Failed to retrieve existing List of Values: {JASPER_RESOURCE_ID}. Status code: {response.status_code}')
        return
    
    items = extract_items(groups)
    
    existing_data['items'] = items

    response = requests.put(jasperserver_endpoint, headers=headers, json=existing_data)
    if response.status_code == 200:
        print(f'JasperServer: Successfully updated List of Values: {JASPER_RESOURCE_ID}')
    else:
        print(f'JasperServer: Failed to update List of Values: {JASPER_RESOURCE_ID}. Status code: {response.status_code}')

def compute_groups_hash(groups):
    groups_str = str(groups)
    return hashlib.sha256(groups_str.encode('utf-8')).hexdigest()

if __name__ == "__main__":
    last_known_hash = None
    while True:
        keycloak_token = get_keycloak_token()
        jasper_token = get_jasperserver_token()
        if keycloak_token and jasper_token:
            groups = get_keycloak_groups(keycloak_token)
            if groups:
                current_hash = compute_groups_hash(groups)
                if last_known_hash != current_hash:
                    print('Changes detected in Keycloak groups, updating JasperServer...')
                    update_jasper_group_list(jasper_token, groups)
                    last_known_hash = current_hash
                else:
                    print('No changes detected in Keycloak groups.')
        else:
            print('Failed to obtain tokens')
        time.sleep(300)
