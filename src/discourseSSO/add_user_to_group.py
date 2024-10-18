import requests
from dotenv import load_dotenv
import os

discourse_url = os.getenv('DISCOURSE_URL')
api_key = os.getenv('API_KEY')
admin_username = os.getenv('ADMIN_USERNAME')

def add_staff_to_private_group(username,affilation):
    is_student = check_if_student(affilation)
    if not is_student:

        headers = {
        "Api-Key": api_key,
        "Api-Username": admin_username,
        }

        data = {
            "usernames":f"{username}"
        }
        try:
            response = requests.put(discourse_url, headers=headers, json=data)
        except Exception as e:
            print(e)

def check_if_student(affilation):
    affiliation_list = affilation.split(';')
    for affilation in affiliation_list:
        if 'student' in affilation:
            for affilation in affiliation_list:
                if 'staff' in affilation:
                    return False
            return True
    return False

