import frappe
from frappe import _
from frappe import utils
from vms.functions import verify_hash, generate_hash
import os.path
import requests
import json
import base64
from frappe.sessions import Session, clear_sessions, delete_session
from frappe.exceptions import DoesNotExistError
from frappe.utils.password import update_password
import re
import random


def verify_request(request):
  # if request.method == "POST":
  request_hash = request.headers.get("vms-request-hash")
  return verify_hash("@Sydani_Visitors_Management_System->", request_hash)

def save_image(request, img_name):
  save_path = os.path.join(os.path.expanduser('~'), 
  'frappe-bench/sites/office.sydani.org/public/files/vms', 
  img_name)

  uploaded_file = request.files['picture']

  with open(save_path, 'wb') as new_file:
    new_file.write(uploaded_file.read())

  return f"/files/vms/{img_name}"

def generate_keys(user):
    user_doc = frappe.get_doc("User", user)
    sid = frappe.session.user

    if frappe.cache().get_value(user):
        user_doc.api_secret = frappe.cache().get_value(user)
        user_doc.sid = frappe.cache().get_value(f'{user}_sid')
    else:
        api_secret = frappe.generate_hash(length=15)
        frappe.cache().set_value(user, api_secret)
        frappe.cache().set_value(f'{user}_sid', sid)

        user_doc.api_secret = frappe.cache().get_value(user)
    if not user_doc.api_key:
        user_doc.api_key = frappe.generate_hash(length=15)

    user_doc.save(ignore_permissions=True)
    user_doc.api_secret = frappe.cache().get_value(user)
    return user_doc

def create_user(names, password=None):
    for name in names:
        name_list = name['Name'].split(' ')

        firstname = name_list[0].title()
        lastname = name_list[1].title()
        
        username = name['Email']
        if password == None:
            password = f'{firstname.lower()}@{random.randint(1000, 9999)}'

        role = 'VMSUser'

        rol_name = frappe.get_value('Role', {'role_name': role}, 'name')

        new_user = frappe.get_doc({
            "doctype": "User",
            "email": username,
            "first_name": firstname,
            "last_name": lastname,
            "password": password,
            "roles": [{'role': rol_name}]
        })

        new_user.insert()
        frappe.db.commit()

        print({'email': username, 'password': password})
        reset_user_password(username, password)

def set_error(code):
    message = ''

    if code == 400:
        message = 'The old password you provided does not match our records. Please verify and try again.'
    elif code == 401:
        message = 'Authentication Error'
    elif code == 403:
        message = "You dont have permission to access the requested resource"
    elif code == 404:
        message = 'No record found'
    elif code == 505:
        message = 'Internal Server Error'

    frappe.response['message'] = {
        'success': False,
        'status': code,
        'message': message
    }


@frappe.whitelist(allow_guest=True)
def login(email, password):
    try:
        login_manager = frappe.auth.LoginManager()
        login_manager.authenticate(user=email, pwd=password)
        login_manager.post_login()
    except frappe.exceptions.AuthenticationError:
        frappe.clear_messages()
        set_error(code=401)
        return

    user = generate_keys(email)
    roles = frappe.permissions.get_roles(user=email)

    user_roles = [x for x in roles if x not in ['All', 'Guest']]
  
    frappe.response["message"] = {
        "success": 1,
        "message": "Authenticated",
        "sid": frappe.session.sid,
        "api_key": user.api_key,
        "api_secret": user.api_secret,
        "username": user.username,
        "email": user.email,
        'roles': user_roles
    }


@frappe.whitelist()
def logout(email):
    frappe.sessions.clear_sessions(
        user=email, keep_current=False, device=None, force=True)
    frappe.clear_cache(user=email)
    frappe.local.login_manager.logout()
    frappe.cache().delete_value(email)
    generate_keys(email)
    frappe.response['message'] = {'success': 1, "message": 'Logged out'}

def reset_user_password(user_email, new_password):
    print(new_password)
    user = frappe.get_doc("User", user_email)
    if user:
        update_password(user.name, new_password)
        return f"Password reset for user: {user_email}"
    else:
        return f"User not found: {user_email}"


@frappe.whitelist()
def employees():
  if verify_request(frappe.request):
    employees = frappe.db.sql(f"""
      SELECT employee_name, user_id 
      FROM `tabEmployee` 
      WHERE status = 'Active'""", 
    as_dict=True)
    return employees
  else:
    set_error(code=401)
    return

@frappe.whitelist()
def sign_in(
  checkin_type,
  full_name,
  phone_number,
  address,
  purpose_of_visit,
  state_purpose_of_visit,
  who_are_you_meeting,
  organization_name,
  organization_address,
  number_of_visitors, 
  visitors_tag):

  if verify_request(frappe.request):
    try:
      # img_name = f"{full_name.replace(' ', '-')}-{phone_number[-5:]}.jpg"
      # picture = save_image(frappe.request, img_name)
      
      new_visitor_obj = {
        'doctype': 'Visitors Management System',
        'checkin_type': checkin_type,
        'full_name': full_name,
        'phone_number': phone_number,
        'address': address,
        'purpose_of_visit': purpose_of_visit,
        'state_purpose_of_visit': state_purpose_of_visit,
        'who_are_you_meeting': who_are_you_meeting,
        # 'picture': picture,
        'checkin_time': utils.now(),
        'organization_name': organization_name,
        'organization_address': organization_address,
        'number_of_visitors': number_of_visitors,
        'visitors_tag': visitors_tag
      }

      frappe.get_doc(new_visitor_obj).save(ignore_permissions=True)
      frappe.response['message'] = {
        'success': True,
        'status': 200,
        'message': 'Signed In'
       }
    except Exception as e:
      set_error(code=505)
      return
  else:
    set_error(code=401)
    return

@frappe.whitelist(allow_guest=True)
def get_visitor(phone_number=None, visitors_tag=None):
  if verify_request(frappe.request):

    if phone_number:
      filter = f"phone_number = '{phone_number}'"
    elif visitors_tag:
      filter = f"visitors_tag = '{visitors_tag}'"
    else:
      set_error(code=505)
      return
    # CONCAT('https://office.sydani.org', picture) as picture
    visitor = frappe.db.sql(f"""
    SELECT full_name, phone_number, checkin_time, visitors_tag, number_of_visitors  
    FROM `tabVisitors Management System` 
    WHERE {filter} 
    AND (checkout_time = '' 
    OR checkout_time IS NULL) 
    ORDER BY checkin_time DESC
    """, as_dict=True)
    if len(visitor) >= 1:
      return visitor[0]
    else:
      set_error(code=404)
      return
  else:
    set_error(code=401)
    return

@frappe.whitelist(allow_guest=True)
def sign_out(phone_number=None, visitors_tag=None):
  if verify_request(frappe.request):
    if phone_number:
      filter = f"phone_number = '{phone_number}'"
    elif visitors_tag:
      filter = f"visitors_tag = '{visitors_tag}'"
    else:
      set_error(code=505)
      return

    visitor_checkins = frappe.db.sql(f"""
    SELECT name
    FROM `tabVisitors Management System` 
    WHERE {filter} 
    AND (checkout_time = '' 
    OR checkout_time IS NULL) """, as_dict=True)
    for checkin in visitor_checkins:
      checkin_doc = frappe.get_doc('Visitors Management System', checkin.name)
      checkin_doc.checkout_time = utils.now()
      checkin_doc.save(ignore_permissions=True)
      frappe.db.commit()
    frappe.response['message'] = {
        'success': True,
        'status': 200,
        'message': 'Logged out'
    }
  else:
    set_error(code=401)
    return


# def new_user():
#   create_user(names = [
#     {'Name': 'VMS User', 'Email': 'vms@sydani.org'}
#   ])