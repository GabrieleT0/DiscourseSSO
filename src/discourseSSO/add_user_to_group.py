import requests
from dotenv import load_dotenv
import os

discourse_url = os.getenv('DISCOURSE_URL')
api_key = os.getenv('API_KEY')
admin_username = os.getenv('ADMIN_USERNAME')

def add_users_to_group(username,affilation):
    is_student = check_if_student(affilation)
    if not is_student:
        url = discourse_url + '/groups' + '/47' + '/members.json'
        headers = {
        "Api-Key": api_key,
        "Api-Username": admin_username,
        }

        data = {
            "usernames":f"{username}"
        }
        try:
            r = requests.put(url, headers=headers, json=data)
            
            return True
        except Exception as e:
            print("Add to private group error: ",e)
            return False
    else:
        url = discourse_url + '/groups' + '/48' + '/members.json'
        headers = {
        "Api-Key": api_key,
        "Api-Username": admin_username,
        }

        data = {
            "usernames":f"{username}"
        }
        try:
            r = requests.put(url, headers=headers, json=data)
            
            return True
        except Exception as e:
            print("Add to student group error: ",e)
            return False

def check_if_student(affilation):
    affiliation_list = affilation.split(';')
    for affilation in affiliation_list:
        if 'student' in affilation:
            for affilation in affiliation_list:
                if 'staff' in affilation or 'faculty' in affilation:
                    return False
            return True
    return False

def clean_bio(username):
    username = username.lower()
    url_request = discourse_url + '/u/' + username + '.json'

    headers = {
        "Api-Key": api_key,
        "Api-Username": admin_username,
    }

    data = {
        "bio_raw":""
    }

    try:
        r = requests.put(url_request, headers=headers, json=data)

        return True
    except Exception as e:
        print("Clean Bio error: ", e)
        return False
