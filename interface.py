import tkinter as tk
import re
from time import sleep
from typing import Dict, List, Tuple
import argparse


#!/usr/bin/env python3

# enable test mode via command-line flag --test
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--test", action="store_true", help="Enable test mode (pre-fill test credentials)")
_args, _ = parser.parse_known_args()
TEST_MODE = _args.test

# global variables to store user information
# these will be used to pass data between pages
# in a real application, these would be replaced with a proper user session management system
from backend import Session, BackendAPI

def main():
    root = tk.Tk()
    root.title("Multi-Page Tkinter Demo")
    root.geometry("800x800")

    # Container holds all pages (Frames)
    container = tk.Frame(root)
    container.pack(fill="both", expand=True)

    class LoginPage(tk.Frame):
        # login page with Username and password fields
        # label on the left side and entry fields on the right side
        # user login, admin login, signup, and quit buttons at the bottom
        # login button that navigates to PageTwo if passed
        # or shows an error message if failed (login logic not implemented)
        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.session = session

            # allow this page to expand to fill the 800x600 container
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)
            self.controller = controller

            # inner frame uses most of the available space with padding
            inner = tk.Frame(self, bd=8)
            inner.grid(row=0, column=0, sticky="nsew", padx=40, pady=20)

            # make columns/rows inside inner expandable so entries grow with window
            inner.grid_columnconfigure(0, weight=0)   # labels
            inner.grid_columnconfigure(1, weight=1)   # entry widgets expand
            inner.grid_rowconfigure(0, weight=0)
            inner.grid_rowconfigure(1, weight=0)
            inner.grid_rowconfigure(2, weight=0)
            inner.grid_rowconfigure(3, weight=0)
            inner.grid_rowconfigure(4, weight=0)      # space for logs

            label = tk.Label(inner, text="Login Page", font=("Helvetica", 20))
            label.grid(row=0, column=0, columnspan=2, pady=(0, 16))

            tk.Label(inner, text="Username:", anchor="e").grid(row=1, column=0, sticky="e", padx=(0,12), pady=8)
            self.username_entry = tk.Entry(inner)
            self.username_entry.grid(row=1, column=1, sticky="ew", padx=(0,12), pady=8)

            tk.Label(inner, text="Password:", anchor="e").grid(row=2, column=0, sticky="e", padx=(0,12), pady=8)
            self.password_entry = tk.Entry(inner, show="*")
            self.password_entry.grid(row=2, column=1, sticky="ew", padx=(0,12), pady=8)

            # horizontal button bar centered and using more horizontal space
            btn_frame = tk.Frame(inner)
            btn_frame.grid(row=3, column=0, columnspan=2, pady=18, sticky="n")
            btn_frame.grid_columnconfigure(0, weight=1)
            btn_frame.grid_columnconfigure(1, weight=1)
            btn_frame.grid_columnconfigure(2, weight=1)
            btn_frame.grid_columnconfigure(3, weight=1)

            user_login_btn = tk.Button(btn_frame, text="User Login",
                command=self.user_login)
            admin_login_btn = tk.Button(btn_frame, text="Admin Login",
                command=self.admin_login)
            signup_btn = tk.Button(btn_frame, text="Sign Up", 
                command=self.signup)
            quit_btn = tk.Button(btn_frame, text="Quit",
                 command=self.winfo_toplevel().destroy)
            

            # distribute buttons evenly and let them expand a bit
            user_login_btn.grid(row=0, column=0, sticky="ew", padx=8)
            admin_login_btn.grid(row=0, column=1, sticky="ew", padx=8)
            signup_btn.grid(row=0, column=2, sticky="ew", padx=8)
            quit_btn.grid(row=0, column=3, sticky="ew", padx=8)

            # log area for row 4 (for error messages, etc)
            self.log_label = tk.Label(inner, font=("Helvetica", 12), fg="red", text="")
            self.log_label.grid(row=4, column=0, columnspan=2, sticky="nsew")


        def user_login(self):
            # Placeholder for login logic
            # On successful login, navigate to PageTwo
            self.clear_log()
            username = self.username_entry.get().strip()
            password = self.password_entry.get().strip()
            if not username or not password:
                self.log_message("帳號密碼不可為空")
                return
            state, msg, user_data = BackendAPI.login(username=username, password=password)

            if not state:
                self.log_message(msg)
                return
            
            self.session.login(user_data, password)

            self.controller.frames["UserPage"].switched_to()
            self.controller.show_frame("UserPage")
        
        def admin_login(self):
            # Placeholder for admin login logic
            self.clear_log()
            username = self.username_entry.get().strip()
            password = self.password_entry.get().strip()
            if not username or not password:
                self.log_message("帳號密碼不可為空")
                return
            state, msg, user_data = BackendAPI.login(username=username, password=password)
            
            if not state:
                self.log_message(msg)
                return
            elif not user_data.get("role", "") == "admin":
                self.log_message("此帳號非管理員帳號")
                return
            
            self.session.login(user_data, password)
            self.controller.frames["AdminPage"].switched_to()
            self.controller.show_frame("AdminPage")
            
        def signup(self):
            self.session.username = self.username_entry.get()
            self.session.password = self.password_entry.get()
            self.controller.frames["SignUpPage"].switched_to(
                username=self.username_entry.get(),
                password=self.password_entry.get()
            )
            self.controller.show_frame("SignUpPage")
            # Placeholder for signup logic
            pass

        def log_message(self, message):
            self.log_label.config(text=message, fg="red")
        
        def clear_log(self):
            self.log_label.config(text="")
        
        def switched_to(self):
            self.clear_log()
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            # pre-fill the field for convenience upon test
            if TEST_MODE:
                self.username_entry.insert(0, "user4")
                self.password_entry.insert(0, "password4")

    class UserPage(tk.Frame):
        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.session = session
            
            # allow this page to expand to fill the 800x600 container
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)
            self.controller = controller


            inner = tk.Frame(self, bd=8)
            inner.grid(row=0, column=0, sticky="nsew", padx=40, pady=20)


            label = tk.Label(inner, text="User Page", font=("Helvetica", 20))
            label.pack(pady=10, padx=10)

            btn_frame = tk.Frame(inner)
            btn_frame.pack(pady=10, padx=40, fill="x")

            edit_profile_button = tk.Button(btn_frame, text="Edit Password / Delete Account",
                                    command=self.edit_profile)
            edit_profile_button.pack(fill="x", pady=4)

            post_request_button = tk.Button(btn_frame, text="Post Request",
                                     command=self.post_request)
            post_request_button.pack(fill="x", pady=4)

            manage_requests_button = tk.Button(btn_frame, text="Manage Requests",
                                 command=self.manage_requests)
            manage_requests_button.pack(fill="x", pady=4)
            search_requests_button = tk.Button(btn_frame, text="Search Requests",
                                  command=self.search_requests)
            search_requests_button.pack(fill="x", pady=4)

            view_takes_button = tk.Button(btn_frame, text="View Takes",
                                 command=self.view_takes)
            view_takes_button.pack(fill="x", pady=4)

            view_courses_button = tk.Button(btn_frame, text="View Courses",
                                 command=self.view_courses)
            view_courses_button.pack(fill="x", pady=4)

            logout_button = tk.Button(btn_frame, text="Logout",
                                 command=self.logout)
            logout_button.pack(fill="x", pady=4)

            self.log_label = tk.Label(inner, font=("Helvetica", 12), fg="red", text="")
            self.log_label.pack(fill="x", pady=4)
        
        def edit_profile(self):
            self.controller.frames["EditPasswordPage"].switched_to()
            self.controller.show_frame("EditPasswordPage")

        def post_request(self):
            self.controller.frames["PostRequestPage"].switched_to()
            self.controller.show_frame("PostRequestPage")

        def manage_requests(self):
            self.controller.frames["MyRequestResultPage"].switched_to()
            self.controller.show_frame("MyRequestResultPage")

        def search_requests(self):
            self.controller.frames["SearchRequestPage"].switched_to()
            self.controller.show_frame("SearchRequestPage")


        def view_takes(self):
            success, msg, items = BackendAPI.my_taken_by(self.session.u_id)
            if not success:
                self.log_message(msg)
                return
            self.controller.frames["ViewTakeResultPage"].switched_to(items, "UserPage")
            self.controller.show_frame("ViewTakeResultPage")

        def view_courses(self):

            success, msg, items = BackendAPI.my_courses(self.session.u_id)
            if not success:
                self.log_message(msg)
                return
            self.controller.frames["MyCoursesPage"].switched_to(items)
            self.controller.show_frame("MyCoursesPage")

        def logout(self):

            self.session.logout()
            self.controller.frames["LoginPage"].switched_to()
            self.controller.show_frame("LoginPage")
    
        def log_message(self, message):
            self.log_label.config(text=message, fg="red")

        def clear_log(self):
            self.log_label.config(text="")

        def switched_to(self):
            self.clear_log()
    
    class SignUpPage(tk.Frame):
        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)
            self.controller = controller

            # inner frame uses most of the available space with padding
            inner = tk.Frame(self, bd=8)
            inner.grid(row=0, column=0, sticky="nsew", padx=40, pady=20)

            inner.grid_columnconfigure(0, weight=0)   # labels
            inner.grid_columnconfigure(1, weight=1)   # entry widgets expand
            inner.grid_rowconfigure(0, weight=0)
            inner.grid_rowconfigure(1, weight=0)
            inner.grid_rowconfigure(2, weight=0)
            inner.grid_rowconfigure(3, weight=0)
            inner.grid_rowconfigure(4, weight=0)
            inner.grid_rowconfigure(5, weight=0)
            inner.grid_rowconfigure(6, weight=0)
            inner.grid_rowconfigure(7, weight=0)

            label = tk.Label(inner, text="Sign Up Page", font=("Helvetica", 20))
            label.grid(row=0, column=0, columnspan=2, pady=(0, 16))

            tk.Label(inner, text="Username:", anchor="e").grid(row=1, column=0, sticky="e", padx=(0,12), pady=8)
            self.username_entry = tk.Entry(inner)
            self.username_entry.grid(row=1, column=1, sticky="ew", padx=(0,12), pady=8)

            tk.Label(inner, text="Password:", anchor="e").grid(row=2, column=0, sticky="e", padx=(0,12), pady=8)
            self.password_entry = tk.Entry(inner, show="*")
            self.password_entry.grid(row=2, column=1, sticky="ew", padx=(0,12), pady=8)

            # confirm password
            tk.Label(inner, text="Confirm Password:", anchor="e").grid(row=3, column=0, sticky="e", padx=(0,12), pady=8)
            self.confirm_password_entry = tk.Entry(inner, show="*")
            self.confirm_password_entry.grid(row=3, column=1, sticky="ew", padx=(0,12), pady=8)
            
            # real name
            tk.Label(inner, text="Real Name:", anchor="e").grid(row=4, column=0, sticky="e", padx=(0,12), pady=8)
            self.realname_entry = tk.Entry(inner)
            self.realname_entry.grid(row=4, column=1, sticky="ew", padx=(0,12), pady=8)

            # email
            tk.Label(inner, text="Email:", anchor="e").grid(row=5, column=0, sticky="e", padx=(0,12), pady=8)
            self.email_entry = tk.Entry(inner)
            self.email_entry.grid(row=5, column=1, sticky="ew", padx=(0,12), pady=8)

            btn_frame = tk.Frame(inner)
            btn_frame.grid(row=6, column=0, columnspan=2, pady=18, sticky="n")
            btn_frame.grid_columnconfigure(0, weight=1)
            btn_frame.grid_columnconfigure(1, weight=1)

            signup_btn = tk.Button(btn_frame, text="Sign Up",
                command=self.signup)
            cancel_btn = tk.Button(btn_frame, text="Cancel",
                 command=self.cancel)

            # place the buttons in the frame so they are used and visible
            signup_btn.grid(row=0, column=0, sticky="ew", padx=8)
            cancel_btn.grid(row=0, column=1, sticky="ew", padx=8)

            self.log_label = tk.Label(inner, font=("Helvetica", 12), fg="red", text="")
            self.log_label.grid(row=7, column=0, columnspan=2, sticky="nsew")

        def signup(self):

            # pseudo logic for signup

            self.clear_log()
            # validate entries
            username = self.username_entry.get().strip()
            if not username:
                self.log_message("Username cannot be empty.")
                return
            password = self.password_entry.get()
            if not password:
                self.log_message("Password cannot be empty.")
                return
            confirm_password = self.confirm_password_entry.get()
            if password != confirm_password:
                self.log_message("Passwords do not match.")
                return
            realname = self.realname_entry.get().strip()
            if not realname:
                self.log_message("Real name cannot be empty.")
                return
            email = self.email_entry.get().strip()
            if not email:
                self.log_message("Email cannot be empty.")
                return
            
            # more limitations
            if len(username) < 3:
                self.log_message("Username must be at least 3 characters long.")
                return
            if len(password) < 6:
                self.log_message("Password must be at least 6 characters long.")
                return
            if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
                self.log_message("Invalid email format.")
                return
            
            success, msg, user_data = BackendAPI.signup(username, password, confirm_password, realname, email)

            if not success:
                self.log_message(msg)
                return
            
            else:
                self.log_message("Sign up successful! You can now log in.")
                # if successful, navigate to UserPage
                sleep(2)
                self.controller.frames["LoginPage"].switched_to()
                self.controller.show_frame("LoginPage")
                return

        def cancel(self):
            self.controller.show_frame("LoginPage")

        def log_message(self, message):
            self.log_label.config(text=message)
        
        def clear_log(self):
            self.log_label.config(text="")
        
        def switched_to(self, username="", password=""):
            self.clear_log()
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            self.confirm_password_entry.delete(0, tk.END)
            self.realname_entry.delete(0, tk.END)
            self.email_entry.delete(0, tk.END)
            if username:
                self.username_entry.insert(0, username)
            if password:
                self.password_entry.insert(0, password)
        
    class EditPasswordPage(tk.Frame):
        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.session = session
            
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)
            self.controller = controller

            # state variable to track if delete account warning has been issued
            self.delete_account_warning_issued = False

            # inner frame uses most of the available space with padding
            inner = tk.Frame(self, bd=8)
            inner.grid(row=0, column=0, sticky="nsew", padx=40, pady=20)

            inner.grid_columnconfigure(0, weight=0)   # labels
            inner.grid_columnconfigure(1, weight=1)   # entry widgets expand
            inner.grid_rowconfigure(0, weight=0)
            inner.grid_rowconfigure(1, weight=0)
            inner.grid_rowconfigure(2, weight=0)
            inner.grid_rowconfigure(3, weight=0)
            inner.grid_rowconfigure(4, weight=0)
            inner.grid_rowconfigure(5, weight=0)
            inner.grid_rowconfigure(6, weight=0)
            inner.grid_rowconfigure(7, weight=0)

            label = tk.Label(inner, text="Edit Profile Page", font=("Helvetica", 20))
            label.grid(row=0, column=0, columnspan=2, pady=(0, 16))

            tk.Label(inner, text="Username:", anchor="e").grid(row=1, column=0, sticky="e", padx=(0,12), pady=8)
            self.username_entry = tk.Entry(inner)
            self.username_entry.grid(row=1, column=1, sticky="ew", padx=(0,12), pady=8)

            tk.Label(inner, text="Real Name:", anchor="e").grid(row=2, column=0, sticky="e", padx=(0,12), pady=8)
            self.realname_entry = tk.Entry(inner)
            self.realname_entry.grid(row=2, column=1, sticky="ew", padx=(0,12), pady=8)

            tk.Label(inner, text="Old Password:", anchor="e").grid(row=3, column=0, sticky="e", padx=(0,12), pady=8)
            self.old_password_entry = tk.Entry(inner, show="*")
            self.old_password_entry.grid(row=3, column=1, sticky="ew", padx=(0,12), pady=8)


            # confirm password
            tk.Label(inner, text="New Password:", anchor="e").grid(row=4, column=0, sticky="e", padx=(0,12), pady=8)
            self.new_password_entry = tk.Entry(inner, show="*")
            self.new_password_entry.grid(row=4, column=1, sticky="ew", padx=(0,12), pady=8)
            
            # real name
            tk.Label(inner, text="Confirm Password:", anchor="e").grid(row=5, column=0, sticky="e", padx=(0,12), pady=8)
            self.confirm_password_entry = tk.Entry(inner, show="*")
            self.confirm_password_entry.grid(row=5, column=1, sticky="ew", padx=(0,12), pady=8)

            # email

            btn_frame = tk.Frame(inner)
            btn_frame.grid(row=6, column=0, columnspan=3, pady=18, sticky="n")
            btn_frame.grid_columnconfigure(0, weight=1)
            btn_frame.grid_columnconfigure(1, weight=1)
            btn_frame.grid_columnconfigure(2, weight=1)

            confirm_btn = tk.Button(btn_frame, text="Confirm",
                command=self.confirm)
            cancel_btn = tk.Button(btn_frame, text="Cancel",
                 command=self.cancel)
            delete_btn = tk.Button(btn_frame, text="Delete Account",
                 command=self.delete_account)

            # place the buttons in the frame so they are used and visible
            confirm_btn.grid(row=0, column=0, sticky="ew", padx=8)
            cancel_btn.grid(row=0, column=1, sticky="ew", padx=8)
            delete_btn.grid(row=0, column=2, sticky="ew", padx=8)
            self.log_label = tk.Label(inner, font=("Helvetica", 12), fg="red", text="")
            self.log_label.grid(row=7, column=0, columnspan=2, sticky="nsew")

        def confirm(self):
            if self.delete_account_warning_issued:
                # Reset the warning state if cancelling
                self.delete_account_warning_issued = False
                self.clear_log()
                return
            
            self.clear_log()
            username = self.username_entry.get().strip()
            real_name = self.realname_entry.get().strip()
            old_password = self.old_password_entry.get().strip()
            new_password = self.new_password_entry.get().strip()
            confirm_password = self.confirm_password_entry.get().strip()

            if not all([username, real_name, old_password, new_password, confirm_password]):
                self.log_message("Please fill in all fields.")
                return
            
            if new_password != confirm_password:
                self.log_message("New passwords do not match.")
                return
            
            success, msg = BackendAPI.edit_password(
                username,
                real_name,
                old_password,
                new_password
            )

            if not success:
                self.log_message(msg)
                return

            self.log_message("Password changed successfully.")
            sleep(2)
            self.controller.frames["UserPage"].switched_to()
            self.controller.show_frame("UserPage")


        def cancel(self):
            if self.delete_account_warning_issued:
                # Reset the warning state if cancelling
                self.delete_account_warning_issued = False
                self.clear_log()
                return
            self.controller.show_frame("UserPage")
        
        def delete_account(self):
            self.clear_log()
                                    
            username = self.username_entry.get().strip()
            real_name = self.realname_entry.get().strip()
            old_password = self.old_password_entry.get().strip()
            
            if not username or not real_name or not old_password:
                self.log_message("Please fill in Username, Real Name, and Old Password to delete account.")
                self.delete_account_warning_issued = False
                return
            # if warning not yet issued, issue it and return
            if not self.delete_account_warning_issued:
                self.log_message("Warning: Press 'Delete Account' again to confirm deletion,\n or press any other button to cancel.")
                self.delete_account_warning_issued = True
                return
            
            success, msg = BackendAPI.delete_account(
                username,
                old_password,
                real_name
            )

            if not success:
                self.log_message(msg)
                self.delete_account_warning_issued = False
                return

            self.session.logout()
            self.delete_account_warning_issued = False
            self.controller.frames["LoginPage"].switched_to()
            self.controller.show_frame("LoginPage")
            return

        def log_message(self, message):
            self.log_label.config(text=message)
        
        def clear_log(self):
            self.log_label.config(text="")
        
        def switched_to(self):
            self.clear_log()
            self.username_entry.delete(0, tk.END)
            self.realname_entry.delete(0, tk.END)
            self.new_password_entry.delete(0, tk.END)
            self.confirm_password_entry.delete(0, tk.END)
            self.old_password_entry.delete(0, tk.END)
            self.delete_account_warning_issued = False

            self.username_entry.insert(0, self.session.username)

    class PostRequestPage(tk.Frame):
        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.cache = {}
            self.controller = controller
            self.session = session
            
            # allow this page to expand to fill the 800x600 container
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)

            inner = tk.Frame(self, bd=8)
            inner.grid(row=0, column=0, sticky="nsew", padx=40, pady=20)

            # Add more widgets for posting requests here
            inner.grid_columnconfigure(0, weight=0)   # labels
            inner.grid_columnconfigure(1, weight=1)   # entry widgets expand
            inner.grid_rowconfigure(0, weight=0)
            inner.grid_rowconfigure(1, weight=0)
            inner.grid_rowconfigure(2, weight=0)
            inner.grid_rowconfigure(3, weight=0)
            inner.grid_rowconfigure(4, weight=0)
            inner.grid_rowconfigure(5, weight=0)
            inner.grid_rowconfigure(6, weight=0)
            inner.grid_rowconfigure(7, weight=0) 
            inner.grid_rowconfigure(8, weight=1) # description expands
            inner.grid_rowconfigure(9, weight=0)
            inner.grid_rowconfigure(10, weight=0)


            label = tk.Label(inner, text="Post Request Page", font=("Helvetica", 20))
            label.grid(row=0, column=0, columnspan=2, pady=(0, 16))

            tk.Label(inner, text="Username:", anchor="e").grid(row=1, column=0, sticky="e", padx=(0,12), pady=8)
            self.username_label = tk.Label(inner, text="", anchor="w")
            self.username_label.grid(row=1, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Role:", anchor="e").grid(row=2, column=0, sticky="e", padx=(0,12), pady=8)
            self.role_var = tk.StringVar(value="student")
            self.role_menu = tk.OptionMenu(inner, self.role_var, "teacher", "student")
            self.role_menu.grid(row=2, column=1, sticky="w", padx=(0,12), pady=8)
            self.role_entry = self.role_var

            # subject entry
            tk.Label(inner, text="Subject:", anchor="e").grid(row=3, column=0, sticky="e", padx=(0,12), pady=8)
            self.subject_entry = tk.Entry(inner)
            self.subject_entry.grid(row=3, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Target Gradeyear:", anchor="e").grid(row=4, column=0, sticky="e", padx=(0,12), pady=8)
            gradeyear_frame = tk.Frame(inner)
            # create 8 expandable columns so the checkbuttons are distributed evenly
            for c in range(8):
                gradeyear_frame.grid_columnconfigure(c, weight=1)
            gradeyear_frame.grid(row=4, column=1, sticky="w", padx=(0,12), pady=8)

            self.gyear_vars = []
            self.gyear_buttons = []
            for i in range(1, 9):
                var = tk.IntVar(value=0)
                btn = tk.Checkbutton(
                    gradeyear_frame,
                    text=str(i),
                    variable=var,
                    indicatoron=False,   # makes the checkbutton look like a toggle button
                    width=3,
                    padx=2,
                    pady=2
                )
                btn.grid(row=0, column=i-1, padx=2)
                self.gyear_vars.append(var)
                self.gyear_buttons.append(btn)
            
            tk.Label(inner, text="Reward (NT$/hr):", anchor="e").grid(row=5, column=0, sticky="e", padx=(0,12), pady=8)
            self.reward_entry = tk.Entry(inner)
            self.reward_entry.grid(row=5, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Location:", anchor="e").grid(row=6, column=0, sticky="e", padx=(0,12), pady=8)
            self.location_entry = tk.Entry(inner)
            self.location_entry.grid(row=6, column=1, sticky="w", padx=(0,12), pady=8)
            tk.Label(inner, text="Time:", anchor="e").grid(row=7, column=0, sticky="e", padx=(0,12), pady=8)
            
            # Time selection with popup button
            time_frame = tk.Frame(inner)
            time_frame.grid(row=7, column=1, sticky="w", padx=(0,12), pady=8)
            
            self.time_slots = [False for _ in range(24*7)]  # list to hold time slot selections
            self.time_display = tk.Label(time_frame, text="No times selected", anchor="w", width=30, relief="sunken", bd=1)
            self.time_display.pack(side="left", padx=(0, 8))
            
            time_select_btn = tk.Button(time_frame, text="Select Times", command=self.open_new_time_selector)
            time_select_btn.pack(side="left")

            tk.Label(inner, text="Description:", anchor="ne").grid(row=8, column=0, sticky="ne", padx=(0,12), pady=8)
            self.description_entry = tk.Text(inner, height=10, width=50)
            self.description_entry.grid(row=8, column=1, sticky="ew", padx=(0,12), pady=8)

            self.log_label = tk.Label(inner, font=("Helvetica", 12), fg="red", text="")
            self.log_label.grid(row=9, column=0, columnspan=2, sticky="nsew")

            btn_frame = tk.Frame(inner)
            btn_frame.grid(row=10, column=0, columnspan=2, pady=18, sticky="n")
            btn_frame.grid_columnconfigure(0, weight=1)
            btn_frame.grid_columnconfigure(1, weight=1)

            post_btn = tk.Button(btn_frame, text="Post Request",
                command=self.post_request)
            cancel_btn = tk.Button(btn_frame, text="Cancel",
                 command=self.cancel)
            # place the buttons in the frame so they are used and visible
            post_btn.grid(row=0, column=0, sticky="ew", padx=8)
            cancel_btn.grid(row=0, column=1, sticky="ew", padx=8)

        
        def open_new_time_selector(self):
            """Open popup dialog for time selection"""
            dialog = TimeSelectionDialog(self, self.time_slots)
            self.wait_window(dialog)
            # Update display after dialog closes
            self.update_time_display()
        
        def update_time_display(self):
            """Update the time display label based on selected slots"""
            selected_count = sum(self.time_slots)
            if selected_count == 0:
                self.time_display.config(text="No times selected")
            else:
                self.time_display.config(text=f"{selected_count} time slot(s) selected")
        
        def get_selected_times(self):
            """convert select time to bitstring"""
            return ''.join(['1' if slot else '0' for slot in self.time_slots])
        
        def get_gradeyears(self):
            """Get bitstring of selected gradeyears from checkbuttons"""
            if not self.gyear_vars:
                return None  # default to all selected if not initialized
            result = ''.join(['1' if var.get() == 1 else '0' for var in self.gyear_vars])
            if result == '00000000':
                return None  # default to all selected if none are explicitly chosen
            return result

        def post_request(self):
            
            # post_request(u_id, role, target_gradeyear, subject, request_detail, reward, place, time_bits=None)
            self.clear_log()
            u_id = self.session.u_id
            role = self.role_var.get()
            subject = self.subject_entry.get().strip()
            target_gradeyear = self.get_gradeyears()
            reward_str = self.reward_entry.get().strip()
            location = self.location_entry.get().strip()
            time_bits = self.get_selected_times()
            description = self.description_entry.get("1.0", tk.END).strip()
            if not subject:
                self.log_message("Subject cannot be empty.")
                return
            if '1' not in target_gradeyear:
                self.log_message("Please select at least one target gradeyear.")
                return
            if not reward_str.isdigit() or int(reward_str) <= 0:
                self.log_message("Reward must be a positive integer.")
                return
            reward = int(reward_str)
            if not location:
                self.log_message("Location cannot be empty.")
                return
            if '1' not in time_bits:
                self.log_message("Please select at least one available time slot.")
                return
            if not description:
                self.log_message("Description cannot be empty.")
                return
            aggr = {
                "u_id": u_id,
                "role": role,
                "target_gradeyear": target_gradeyear,
                "subject": subject,
                "request_detail": description,
                "reward": reward,
                "place": location,
                "time_bits": time_bits
            }
            # simple cache to prevent duplicate submissions
            if self.cache == aggr:
                self.log_message("This request has already been posted.")
                return
            
            self.cache = aggr
            success, msg, r_id = BackendAPI.post_request(**aggr)

            if success:
                self.log_message("Request posted successfully.")
                sleep(2)
                self.controller.frames["UserPage"].switched_to()
                self.controller.show_frame("UserPage")
            else:
                self.log_message(f"Failed to post request: {msg}")

        def cancel(self):
            self.controller.show_frame("UserPage")

        def log_message(self, message):
            self.log_label.config(text=message)
        
        def clear_log(self):
            self.log_label.config(text="")

        def switched_to(self):
            # reset all fields
            self.clear_log()
            self.username_label.config(text=self.session.username)
            self.subject_entry.delete(0, tk.END)
            self.role_var.set("student")
            for i in range(8):
                self.gyear_vars[i].set(0)
            self.reward_entry.delete(0, tk.END)
            self.reward_entry.insert(0, "")
            self.location_entry.delete(0, tk.END)
            self.location_entry.insert(0, "")
            self.time_slots = [False] * (24 * 7)
            
            self.update_time_display()
            self.description_entry.delete("1.0", tk.END)
            self.description_entry.insert("1.0", "")

    class TimeSelectionDialog(tk.Toplevel):
        """Popup dialog for selecting 24x7 time slots"""
        
        # Class attribute for button colors: (available, disabled, selected) -> color
        colors = {
            (True, False, False): "white",
            (True, False, True): "lightgreen",
            (False, False, False): "black",
            (False, False, True): "red",
            (True, True, False): "white",
            (True, True, True): "blue",
            (False, True, False): "white",
            (False, True, True): "blue"
        }
        
        def __init__(self, parent, time_slots_list, disabled=False, available=None):
            super().__init__(parent)
            self.title("Select Available Times")
            self.geometry("900x700")
            self.time_slots = time_slots_list
            self.available_slots = available if available else [True for _ in range(24*7)]
            self.disabled = disabled
            

            
            # Make dialog modal
            self.transient(parent)
            self.grab_set()
            
            # Main container with scrollbar
            main_frame = tk.Frame(self)
            main_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            if not disabled:
                # Instructions
                instruction_label = tk.Label(main_frame, 
                    text="Click on time slots to toggle your availability (green = available)",
                    font=("Helvetica", 10))
                instruction_label.pack(pady=(0, 10))
            else:
                instruction_label = tk.Label(main_frame, 
                    text="Time slots are shown for reference only.",
                    font=("Helvetica", 10))
                instruction_label.pack(pady=(0, 10))
            
            # Create canvas with scrollbar for the grid
            canvas = tk.Canvas(main_frame)
            scrollbar = tk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
            scrollable_frame = tk.Frame(canvas)
            
            scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )
            
            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            
            # Build the 24x7 grid
            days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
            
            # Header row with day labels
            tk.Label(scrollable_frame, text="Hour", width=6, relief="ridge", bg="lightgray").grid(row=0, column=0, sticky="nsew")
            for col, day in enumerate(days, start=1):
                tk.Label(scrollable_frame, text=day, width=8, relief="ridge", bg="lightgray").grid(row=0, column=col, sticky="nsew")
            
            # Create grid of checkbuttons (24 hours x 7 days)
            self.time_buttons = {}
            for hour in range(24):
                # Hour label
                hour_label = f"{hour:02d}:00"
                tk.Label(scrollable_frame, text=hour_label, width=6, relief="ridge", bg="lightgray").grid(row=hour+1, column=0, sticky="nsew")
                
                for day_idx, day in enumerate(days):
                    # Get current state or default to False
                    index = day_idx * 24 + hour
                    current_state = self.time_slots[index]
                    
                    btn = tk.Button(
                        scrollable_frame,
                        text="",
                        width=8,
                        height=1,
                        relief="raised",
                        bg=self.colors[(self.available_slots[index], disabled, current_state)],
                        command=lambda idx=index: self.toggle_slot(idx)
                    )
                    btn.grid(row=hour+1, column=day_idx+1, sticky="nsew", padx=1, pady=1)

                    if not self.available_slots[index]:
                        btn.config(state="disabled")
                    self.time_buttons[index] = btn
            
            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            
            # Bottom button frame
            btn_frame = tk.Frame(self)
            btn_frame.pack(fill="x", padx=10, pady=(5, 10))
            
            clear_btn = tk.Button(btn_frame, text="Clear All", command=self.clear_all, state="disabled" if self.disabled else "normal")
            clear_btn.pack(side="left", padx=5)
            
            select_all_btn = tk.Button(btn_frame, text="Select All", command=self.select_all, state="disabled" if self.disabled else "normal")
            select_all_btn.pack(side="left", padx=5)
            
            done_btn = tk.Button(btn_frame, text="Done", command=self.destroy)
            done_btn.pack(side="right", padx=5)
        
        def toggle_slot(self, key):
            """Toggle a time slot selection"""
            assert 0 <= key < len(self.time_slots), "Invalid time slot key"
            assert self.available_slots[key] == True, "Cannot toggle unavailable slot"

            if self.disabled:
                return

            if not self.available_slots[key]:
                return

            self.time_slots[key] = not self.time_slots[key]
            btn = self.time_buttons[key]
            btn.config(bg=self.colors[(self.available_slots[key], self.disabled, self.time_slots[key])])
        
        def clear_all(self):
            """Clear all selections"""
            if self.disabled:
                return
            for i in range(len(self.time_slots)):
                self.time_slots[i] = False
                self.time_buttons[i].config(bg=self.colors[(self.available_slots[i], self.disabled, False)])
        
        def select_all(self):
            """Select all time slots"""
            for i in range(len(self.time_slots)):
                self.time_slots[i] = self.available_slots[i]
                self.time_buttons[i].config(bg=self.colors[(self.available_slots[i], self.disabled, self.time_slots[i])])

    class MyRequestResultPage(tk.Frame):

        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.controller = controller
            self.session = session

            label = tk.Label(self, text="My Request Result Page", font=("Helvetica", 20))
            label.pack(pady=10, padx=10)

            # scrollable listbox you can append items to
            list_frame = tk.Frame(self)
            list_frame.pack(fill="both", expand=True, padx=10, pady=10)

            scrollbar = tk.Scrollbar(list_frame, orient="vertical")
            scrollbar.pack(side="right", fill="y")

            # use single selection so clicks map cleanly to one item
            self.result_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, selectmode="browse")
            self.result_listbox.pack(side="left", fill="both", expand=True)

            scrollbar.config(command=self.result_listbox.yview)

            # bind double-click and Enter to activate item
            self.result_listbox.bind("<Double-Button-1>", lambda e: self._on_item_activate())
            self.result_listbox.bind("<Return>", lambda e: self._on_item_activate())

            # log label
            self.log_label = tk.Label(self, font=("Helvetica", 12), fg="red", text="")
            self.log_label.pack(pady=5)

            # back button
            back_button = tk.Button(self, text="Back",
                                command=self.go_back)
            back_button.pack(pady=10)

        def append_item(self, item=None):
            """
            Append an item to the listbox. Optionally provide a callback
            function that will be called when the item is activated.
            The callback receives (text, index).
            """
            if item is None:
                text = "No requests found."
            else:
                text = f"#{item['r_id']} | {item['subject']} | {item['role']} | {item['gradeyear_display']}"
            self.result_listbox.insert(tk.END, text)
            # keep the newest item visible
            self.result_listbox.see(tk.END)

        def _on_item_activate(self):
            selection = self.result_listbox.curselection()
            if not selection:
                return
            idx = selection[0] # get the selected index
            item_text = self.result_listbox.get(idx)
            callback = self.enter_item(self.items[idx])
            if callback:
                callback(item_text, idx)

        def clear_items(self):
            self.result_listbox.delete(0, tk.END)
        
        def load_items(self, items):
            self.items = items
            self.clear_items()
            for item in items:
                self.append_item(item)

        def enter_item(self, item):
            if item is None:
                print("No item to enter.")
                return
            self.controller.frames["EditRequestPage"].switched_to(item)
            self.controller.show_frame("EditRequestPage")

        def go_back(self):
            self.controller.show_frame("UserPage")

        def switched_to(self):
            self.clear_items()
            # example: append an item with a custom callback
            success, msg, items = BackendAPI.get_my_requests(self.session.u_id)
            if not success:
                self.log_message(f"Error loading requests: {msg}")
                return
            if not items:
                self.clear_items()
                self.append_item(None)
                self.items = []
                return
            self.load_items(items)
            self.items = items
        
        def log_message(self, message):
            self.log_label.config(text=message)
        
        def clear_log(self):
            self.log_label.config(text="")

    class EditRequestPage(tk.Frame):
        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.controller = controller
            self.session = session

            self.delete_confirmation_issued = False
            
            # allow this page to expand to fill the 800x600 container
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)

            inner = tk.Frame(self, bd=8)
            inner.grid(row=0, column=0, sticky="nsew", padx=40, pady=20)

            # Add more widgets for posting requests here
            inner.grid_columnconfigure(0, weight=0)   # labels
            inner.grid_columnconfigure(1, weight=1)   # entry widgets expand
            inner.grid_rowconfigure(0, weight=0)
            inner.grid_rowconfigure(1, weight=0)
            inner.grid_rowconfigure(2, weight=0)
            inner.grid_rowconfigure(3, weight=0)
            inner.grid_rowconfigure(4, weight=0)
            inner.grid_rowconfigure(5, weight=0)
            inner.grid_rowconfigure(6, weight=0)
            inner.grid_rowconfigure(7, weight=0)
            inner.grid_rowconfigure(8, weight=1) # description expands
            inner.grid_rowconfigure(9, weight=0)
            inner.grid_rowconfigure(10, weight=0)


            label = tk.Label(inner, text="Edit Request Page", font=("Helvetica", 20))
            label.grid(row=0, column=0, columnspan=2, pady=(0, 16))

            tk.Label(inner, text="Username:", anchor="e").grid(row=1, column=0, sticky="e", padx=(0,12), pady=8)
            self.username_label = tk.Label(inner, text="", anchor="w")
            self.username_label.grid(row=1, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Role:", anchor="e").grid(row=2, column=0, sticky="e", padx=(0,12), pady=8)
            self.role_label = tk.Label(inner, text="", anchor="w")
            self.role_label.grid(row=2, column=1, sticky="w", padx=(0,12), pady=8)

            # subject entry
            tk.Label(inner, text="Subject:", anchor="e").grid(row=3, column=0, sticky="e", padx=(0,12), pady=8)
            self.subject_label = tk.Label(inner, text="", anchor="w")
            self.subject_label.grid(row=3, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Target Gradeyear:", anchor="e").grid(row=4, column=0, sticky="e", padx=(0,12), pady=8)
            gradeyear_frame = tk.Frame(inner)
                # create 8 expandable columns so the checkbuttons are distributed evenly
            for c in range(8):
                gradeyear_frame.grid_columnconfigure(c, weight=1)
            gradeyear_frame.grid(row=4, column=1, sticky="w", padx=(0,12), pady=8)

            self.gyear_vars = []
            self.gyear_buttons = []
            for i in range(1, 9):
                var = tk.IntVar(value=0)
                btn = tk.Checkbutton(
                    gradeyear_frame,
                    text=str(i),
                    variable=var,
                    indicatoron=False,   # makes the checkbutton look like a toggle button
                    width=3,
                    padx=2,
                    pady=2,
                    state="disabled"
                )
                btn.grid(row=0, column=i-1, padx=2)
                self.gyear_vars.append(var)
                self.gyear_buttons.append(btn)
            
            tk.Label(inner, text="Reward (NT$/hr):", anchor="e").grid(row=5, column=0, sticky="e", padx=(0,12), pady=8)
            self.reward_label = tk.Label(inner, text="", anchor="w")
            self.reward_label.grid(row=5, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Location:", anchor="e").grid(row=6, column=0, sticky="e", padx=(0,12), pady=8)
            self.location_label = tk.Label(inner, text="", anchor="w")
            self.location_label.grid(row=6, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Time:", anchor="e").grid(row=7, column=0, sticky="e", padx=(0,12), pady=8)
            
            # Time selection with popup button
            time_frame = tk.Frame(inner)
            time_frame.grid(row=7, column=1, sticky="w", padx=(0,12), pady=8)
            
            self.time_slots = [False for _ in range(24*7)]  # list to hold time slot selections
            self.time_display = tk.Label(time_frame, text="No times selected", anchor="w", width=30, relief="sunken", bd=1)
            self.time_display.pack(side="left", padx=(0, 8))
            
            time_select_btn = tk.Button(time_frame, text="View Times", command=self.open_new_time_selector)
            time_select_btn.pack(side="left")

            tk.Label(inner, text="Description:", anchor="ne").grid(row=8, column=0, sticky="ne", padx=(0,12), pady=8)
            self.description_entry = tk.Text(
                inner,
                height=10,
                width=50,
                wrap="word",
                relief="sunken",
                bd=1,
                state="disabled",
                bg="lightgray"
            )
            self.description_entry.grid(row=8, column=1, sticky="ew", padx=(0,12), pady=8)

            self.log_label = tk.Label(inner, font=("Helvetica", 12), fg="red", text="")
            self.log_label.grid(row=9, column=0, columnspan=2, sticky="nsew")

            btn_frame = tk.Frame(inner)
            btn_frame.grid(row=10, column=0, columnspan=2, pady=18, sticky="n")
            btn_frame.grid_columnconfigure(0, weight=1)
            btn_frame.grid_columnconfigure(1, weight=1)
            btn_frame.grid_columnconfigure(2, weight=1)

            post_btn = tk.Button(btn_frame, text="Delete Request",
                command=self.delete_request)
            cancel_btn = tk.Button(btn_frame, text="Cancel",
                command=self.cancel)
            view_takes_btn = tk.Button(btn_frame, text="View Takes",
                command=self.view_takes)
            # place the buttons in the frame so they are used and visible
            post_btn.grid(row=0, column=0, sticky="ew", padx=8)
            cancel_btn.grid(row=0, column=1, sticky="ew", padx=8)
            view_takes_btn.grid(row=0, column=2, sticky="ew", padx=8)

        
        def open_new_time_selector(self):
            """Open popup dialog for time selection"""
            if self.delete_confirmation_issued:
                self.delete_confirmation_issued = False
                self.clear_log()
                return
            dialog = TimeSelectionDialog(self, self.time_slots, disabled=True, available=self.time_slots)
            self.wait_window(dialog)
            # Update display after dialog closes
            # Only for showing selected times, not editing, so no need to update self.time_slots
            # self.update_time_display()
        
        def update_time_display(self):
            """Update the time display label based on selected slots"""
            selected_count = sum(self.time_slots)
            if selected_count == 0:
                self.time_display.config(text="No times selected")
            else:
                self.time_display.config(text=f"{selected_count} time slot(s) selected")
       
        def delete_request(self):
            if not self.delete_confirmation_issued:
                self.log_message("Press Delete Request again to confirm deletion.")
                self.delete_confirmation_issued = True
                return
            
            success, msg = BackendAPI.delete_request(self.session.u_id, self.r_id)
            if success:
                self.log_message("Request deleted successfully.")
                self.controller.show_frame("UserPage")
            else:
                self.log_message(f"Failed to delete request: {msg}")

        def cancel(self):
            if self.delete_confirmation_issued:
                self.delete_confirmation_issued = False
                self.clear_log()
                return
            self.controller.show_frame("UserPage")
        
        def view_takes(self):
            if self.delete_confirmation_issued:
                self.delete_confirmation_issued = False
                self.clear_log()
                return
            
            success, msg, items = BackendAPI.my_request_taken_by(self.session.u_id, self.r_id)
            self.controller.frames["ViewTakeResultPage"].switched_to(items, "EditRequestPage")
            self.controller.show_frame("ViewTakeResultPage")

        def log_message(self, message):
            self.log_label.config(text=message)

        def clear_log(self):
            self.log_label.config(text="")

        def switched_to(self, item):
            if item is None:
                print("No item to enter.")
                return
            # populate fields from item
            r_id = item.get("r_id", "")
            u_id = item.get("u_id", "")
            role = item.get("role", "")
            subject = item.get("subject", "")
            target_gradeyear = item.get("target_gradeyear", "00000000")
            description = item.get("request_detail", "")
            reward = item.get("reward", 0)
            location = item.get("place", "")
            time_slots_str = item.get("time", "0" * 168)
            for i in range(24*7):
                self.time_slots[i] = (time_slots_str[i] == '1')
            self.update_time_display()
            self.clear_log()
            self.r_id = r_id
            self.u_id = u_id
            self.username_label.config(text=self.session.username)
            for i in range(8):
                if target_gradeyear[i] == '1':
                    self.gyear_vars[i].set(1)
                else:
                    self.gyear_vars[i].set(0)
            self.role_label.config(text=role)
            self.subject_label.config(text=subject)
            self.reward_label.config(text=str(reward))
            self.location_label.config(text=location)
            self.description_entry.config(state="normal")
            self.description_entry.delete("1.0", tk.END)
            self.description_entry.insert("1.0", description)
            self.description_entry.config(state="disabled")

    class SearchRequestPage(tk.Frame):
        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.controller = controller
            self.session = session
            
            # allow this page to expand to fill the 800x600 container
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)

            inner = tk.Frame(self, bd=8)
            inner.grid(row=0, column=0, sticky="nsew", padx=40, pady=20)

            # Add more widgets for posting requests here
            inner.grid_columnconfigure(0, weight=0)   # labels
            inner.grid_columnconfigure(1, weight=1)   # entry widgets expand
            inner.grid_rowconfigure(0, weight=0)
            inner.grid_rowconfigure(1, weight=0)
            inner.grid_rowconfigure(2, weight=0)
            inner.grid_rowconfigure(3, weight=0)
            inner.grid_rowconfigure(4, weight=0)
            inner.grid_rowconfigure(5, weight=0)
            inner.grid_rowconfigure(6, weight=0)
            inner.grid_rowconfigure(7, weight=0) 
            inner.grid_rowconfigure(8, weight=0) # description expands
            inner.grid_rowconfigure(9, weight=0)
            inner.grid_rowconfigure(10, weight=0)


            label = tk.Label(inner, text="Search Request Page", font=("Helvetica", 20))
            label.grid(row=0, column=0, columnspan=2, pady=(0, 16))

            tk.Label(inner, text="Username:", anchor="e").grid(row=1, column=0, sticky="e", padx=(0,12), pady=8)
            self.username_entry = tk.Entry(inner)
            self.username_entry.grid(row=1, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Your Role:", anchor="e").grid(row=2, column=0, sticky="e", padx=(0,12), pady=8)
            self.role_var = tk.StringVar(value="student")
            self.role_menu = tk.OptionMenu(inner, self.role_var, "teacher", "student")
            self.role_menu.grid(row=2, column=1, sticky="w", padx=(0,12), pady=8)
            self.role_entry = self.role_var

            # subject entry
            tk.Label(inner, text="Subject:", anchor="e").grid(row=3, column=0, sticky="e", padx=(0,12), pady=8)
            self.subject_entry = tk.Entry(inner)
            self.subject_entry.grid(row=3, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Target Gradeyear:", anchor="e").grid(row=4, column=0, sticky="e", padx=(0,12), pady=8)
            gradeyear_frame = tk.Frame(inner)
            # create 8 expandable columns so the checkbuttons are distributed evenly
            for c in range(8):
                gradeyear_frame.grid_columnconfigure(c, weight=1)
            gradeyear_frame.grid(row=4, column=1, sticky="w", padx=(0,12), pady=8)

            self.gyear_vars = []
            self.gyear_buttons = []
            for i in range(1, 9):
                var = tk.IntVar(value=0)
                btn = tk.Checkbutton(
                    gradeyear_frame,
                    text=str(i),
                    variable=var,
                    indicatoron=False,   # makes the checkbutton look like a toggle button
                    width=3,
                    padx=2,
                    pady=2
                )
                btn.grid(row=0, column=i-1, padx=2)
                self.gyear_vars.append(var)
                self.gyear_buttons.append(btn)
            
            tk.Label(inner, text="Reward (NT$/hr):", anchor="e").grid(row=5, column=0, sticky="e", padx=(0,12), pady=8)
            reward_frame = tk.Frame(inner)
            reward_frame.grid(row=5, column=1, sticky="w", padx=(0,12), pady=8)
            tk.Label(reward_frame, text="Min:").pack(side="left", padx=(0, 5))
            self.min_reward_entry = tk.Entry(reward_frame, width=8)
            self.min_reward_entry.pack(side="left", padx=(0, 10))
            tk.Label(reward_frame, text="Max:").pack(side="left", padx=(0, 5))
            self.max_reward_entry = tk.Entry(reward_frame, width=8)
            self.max_reward_entry.pack(side="left")

            tk.Label(inner, text="Location:", anchor="e").grid(row=6, column=0, sticky="e", padx=(0,12), pady=8)
            self.location_entry = tk.Entry(inner)
            self.location_entry.grid(row=6, column=1, sticky="w", padx=(0,12), pady=8)
            tk.Label(inner, text="Time:", anchor="e").grid(row=7, column=0, sticky="e", padx=(0,12), pady=8)
            
            # Time selection with popup button
            time_frame = tk.Frame(inner)
            time_frame.grid(row=7, column=1, sticky="w", padx=(0,12), pady=8)
            
            self.time_slots = [True for _ in range(24*7)]  # list to hold time slot selections
            self.time_display = tk.Label(time_frame, text="All times selected", anchor="w", width=30, relief="sunken", bd=1)
            self.time_display.pack(side="left", padx=(0, 8))
            
            time_select_btn = tk.Button(time_frame, text="Select Times", command=self.open_new_time_selector)
            time_select_btn.pack(side="left")

            tk.Label(inner, text="Description Keyword:", anchor="ne").grid(row=8, column=0, sticky="ne", padx=(0,12), pady=8)
            self.description_entry = tk.Entry(inner)
            self.description_entry.grid(row=8, column=1, sticky="w", padx=(0,12), pady=8)

            self.log_label = tk.Label(inner, font=("Helvetica", 12), fg="red", text="")
            self.log_label.grid(row=9, column=0, columnspan=2, sticky="nsew")

            btn_frame = tk.Frame(inner)
            btn_frame.grid(row=10, column=0, columnspan=2, pady=18, sticky="n")
            btn_frame.grid_columnconfigure(0, weight=1)
            btn_frame.grid_columnconfigure(1, weight=1)

            post_btn = tk.Button(btn_frame, text="Search Requests",
                command=self.search_requests)
            cancel_btn = tk.Button(btn_frame, text="Cancel",
                 command=self.cancel)
            # place the buttons in the frame so they are used and visible
            post_btn.grid(row=0, column=0, sticky="ew", padx=8)
            cancel_btn.grid(row=0, column=1, sticky="ew", padx=8)
        
        def get_gradeyears(self):
            """Get bitstring of selected gradeyears from checkbuttons"""
            if not self.gyear_vars:
                return None  # default to all selected if not initialized
            result = ''.join(['1' if var.get() == 1 else '0' for var in self.gyear_vars])
            if result == '00000000':
                return None  # default to all selected if none are explicitly chosen
            return result
        
        def search_requests(self):
            # Implement the search logic here
            # api_search_request(role=None, username=None, subject=None, target_bits=None, request_detail=None, min_reward=None, max_reward=None, place=None):
            username = self.username_entry.get().strip()
            
            # role have to be flipped because searching for requests from others
            if self.role_var.get() == "teacher":
                role = "student"
            elif self.role_var.get() == "student":
                role = "teacher"
            else:
                role = None
                self.log_message("Invalid role selected.")
                return
            
            subject = self.subject_entry.get().strip()

            gradeyear_bits = self.get_gradeyears()
            time_bits = ''.join(['1' if slot else '0' for slot in self.time_slots])

            min_reward_str = self.min_reward_entry.get().strip()
            max_reward_str = self.max_reward_entry.get().strip()
            
            if not min_reward_str.isdigit() and min_reward_str != "":
                self.log_message("Minimum reward must be a number.")
                return
            if not max_reward_str.isdigit() and max_reward_str != "":
                self.log_message("Maximum reward must be a number.")
                return
            
            min_reward = int(min_reward_str) if min_reward_str != "" else None
            max_reward = int(max_reward_str) if max_reward_str != "" else None
            if min_reward is not None and min_reward < 0:
                self.log_message("Minimum reward cannot be negative.")
                return
            if max_reward is not None and max_reward < 0:
                self.log_message("Maximum reward cannot be negative.")
                return
            if min_reward is not None and max_reward is not None and min_reward > max_reward:
                self.log_message("Minimum reward cannot be greater than maximum reward.")
                return

            place = self.location_entry.get().strip()
            description = self.description_entry.get().strip()
            success, msg, items = BackendAPI.search_request(
                role=role,
                username=username if username != "" else None,
                subject=subject if subject != "" else None,
                target_bits=gradeyear_bits,
                time_bits=time_bits,
                request_detail=description if description != "" else None,
                min_reward=min_reward,
                max_reward=max_reward,
                place=place if place != "" else None
            )

            if not success:
                self.log_message(f"Search failed: {msg}")
                return            
            self.controller.frames["SearchRequestResultPage"].switched_to(items)
            self.controller.show_frame("SearchRequestResultPage")

        def cancel(self):
            self.controller.show_frame("UserPage")
        
        def open_new_time_selector(self):
            """Open popup dialog for time selection"""
            dialog = TimeSelectionDialog(self, self.time_slots)
            self.wait_window(dialog)
            # Update display after dialog closes
            self.update_time_display()
        
        def update_time_display(self):
            """Update the time display label based on selected slots"""
            selected_count = sum(self.time_slots)
            if selected_count == 0:
                self.time_slots = [True for _ in range(24*7)] # reset to all selected
                self.time_display.config(text="All times selected")
            elif selected_count == 24*7:
                self.time_display.config(text="All times selected")
            else:
                self.time_display.config(text=f"{selected_count} time slot(s) selected")
        
        def log_message(self, message):
            self.log_label.config(text=message)
        def clear_log(self):
            self.log_label.config(text="")

        def switched_to(self, clear=True):
            self.clear_log()
            if clear:
                self.username_entry.delete(0, tk.END)
                self.role_var.set("student")
                for i in range(8):
                    self.gyear_vars[i].set(0)
                self.subject_entry.delete(0, tk.END)
                self.min_reward_entry.delete(0, tk.END)
                self.min_reward_entry.insert(0, "")
                self.max_reward_entry.delete(0, tk.END)
                self.max_reward_entry.insert(0, "")
                self.location_entry.delete(0, tk.END)
                self.location_entry.insert(0, "")
                self.time_slots = [True] * (24 * 7)
                self.update_time_display()
                self.description_entry.delete(0, tk.END)
                self.description_entry.insert(0, "")
    
    class SearchRequestResultPage(tk.Frame):
        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.controller = controller
            self.session = session

            label = tk.Label(self, text="Search Request Result Page", font=("Helvetica", 20))
            label.pack(pady=10, padx=10)

            # scrollable listbox you can append items to
            list_frame = tk.Frame(self)
            list_frame.pack(fill="both", expand=True, padx=10, pady=10)

            scrollbar = tk.Scrollbar(list_frame, orient="vertical")
            scrollbar.pack(side="right", fill="y")

            # use single selection so clicks map cleanly to one item
            self.result_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, selectmode="browse")
            self.result_listbox.pack(side="left", fill="both", expand=True)

            scrollbar.config(command=self.result_listbox.yview)

            # bind double-click and Enter to activate item
            self.result_listbox.bind("<Double-Button-1>", lambda e: self._on_item_activate())
            self.result_listbox.bind("<Return>", lambda e: self._on_item_activate())

            # log label
            self.log_label = tk.Label(self, font=("Helvetica", 12), fg="red", text="")
            self.log_label.pack(pady=5)

            # back button
            back_button = tk.Button(self, text="Back",
                                command=self.go_back)
            back_button.pack(pady=10)

        def append_item(self, item=None):
            """
            Append an item to the listbox. Optionally provide a callback
            function that will be called when the item is activated.
            The callback receives (text, index).
            """
            if item is None:
                text = "No requests found."
            else:
                text = f"{item['username']} | {item['subject']} | {item['gradeyear_display']} | {item['place']}"
            self.result_listbox.insert(tk.END, text)
            # keep the newest item visible
            self.result_listbox.see(tk.END)

        def _on_item_activate(self):
            selection = self.result_listbox.curselection()
            if not selection:
                return
            idx = selection[0] # get the selected index
            item_text = self.result_listbox.get(idx)
            callback = self.enter_item(self.items[idx])
            if callback:
                callback(item_text, idx)

        def clear_items(self):
            self.result_listbox.delete(0, tk.END)
        
        def load_items(self, items):
            self.items = items
            self.clear_items()
            for item in items:
                self.append_item(item)

        def enter_item(self, item):
            if item is None:
                print("No item to enter.")
                return
            self.controller.frames["ViewRequestDetailPage"].switched_to(item)
            self.controller.show_frame("ViewRequestDetailPage")

        def go_back(self):
            self.controller.frames["SearchRequestPage"].switched_to(clear=False)
            self.controller.show_frame("SearchRequestPage")

        def switched_to(self, items=None):
                       
            if not items:
                self.clear_items()
                self.append_item(None)
                self.items = []
                return
            self.load_items(items)
            self.items = items
        
        def log_message(self, message):
            self.log_label.config(text=message)
        
        def clear_log(self):
            self.log_label.config(text="")
    
    class ViewRequestDetailPage(tk.Frame):
        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.controller = controller
            self.session = session            
            # allow this page to expand to fill the 800x600 container
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)

            inner = tk.Frame(self, bd=8)
            inner.grid(row=0, column=0, sticky="nsew", padx=40, pady=20)

            # Add more widgets for posting requests here
            inner.grid_columnconfigure(0, weight=0)   # labels
            inner.grid_columnconfigure(1, weight=1)   # entry widgets expand
            inner.grid_rowconfigure(0, weight=0)
            inner.grid_rowconfigure(1, weight=0)
            inner.grid_rowconfigure(2, weight=0)
            inner.grid_rowconfigure(3, weight=0)
            inner.grid_rowconfigure(4, weight=0)
            inner.grid_rowconfigure(5, weight=0)
            inner.grid_rowconfigure(6, weight=0)
            inner.grid_rowconfigure(7, weight=0)
            inner.grid_rowconfigure(8, weight=0)
            inner.grid_rowconfigure(9, weight=1) # description expands
            inner.grid_rowconfigure(10, weight=0)
            inner.grid_rowconfigure(11, weight=0)


            label = tk.Label(inner, text="Request Detail Page", font=("Helvetica", 20))
            label.grid(row=0, column=0, columnspan=2, pady=(0, 16))

            tk.Label(inner, text="Username:", anchor="e").grid(row=1, column=0, sticky="e", padx=(0,12), pady=8)
            self.username_label = tk.Label(inner, text="", anchor="w")
            self.username_label.grid(row=1, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Real Name:", anchor="e").grid(row=2, column=0, sticky="e", padx=(0,12), pady=8)
            self.real_name_label = tk.Label(inner, text="", anchor="w")
            self.real_name_label.grid(row=2, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Role:", anchor="e").grid(row=3, column=0, sticky="e", padx=(0,12), pady=8)
            self.role_label = tk.Label(inner, text="", anchor="w")
            self.role_label.grid(row=3, column=1, sticky="w", padx=(0,12), pady=8)
            # subject entry
            tk.Label(inner, text="Subject:", anchor="e").grid(row=4, column=0, sticky="e", padx=(0,12), pady=8)
            self.subject_label = tk.Label(inner, text="", anchor="w")
            self.subject_label.grid(row=4, column=1, sticky="w", padx=(0,12), pady=8)
            
            tk.Label(inner, text="Target Gradeyear:", anchor="e").grid(row=5, column=0, sticky="e", padx=(0,12), pady=8)
            gradeyear_frame = tk.Frame(inner)
                # create 8 expandable columns so the checkbuttons are distributed evenly
            for c in range(8):
                gradeyear_frame.grid_columnconfigure(c, weight=1)
            gradeyear_frame.grid(row=5, column=1, sticky="w", padx=(0,12), pady=8)

            self.gyear_vars = []
            self.gyear_buttons = []
            for i in range(1, 9):
                var = tk.IntVar(value=0)
                btn = tk.Checkbutton(
                    gradeyear_frame,
                    text=str(i),
                    variable=var,
                    indicatoron=False,   # makes the checkbutton look like a toggle button
                    width=3,
                    padx=2,
                    pady=2,
                    state="disabled"
                )
                btn.grid(row=0, column=i-1, padx=2)
                self.gyear_vars.append(var)
                self.gyear_buttons.append(btn)
            
            tk.Label(inner, text="Reward (NT$/hr):", anchor="e").grid(row=6, column=0, sticky="e", padx=(0,12), pady=8)
            self.reward_label = tk.Label(inner, text="", anchor="w")
            self.reward_label.grid(row=6, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Location:", anchor="e").grid(row=7, column=0, sticky="e", padx=(0,12), pady=8)
            self.location_label = tk.Label(inner, text="", anchor="w")
            self.location_label.grid(row=7, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Time:", anchor="e").grid(row=8, column=0, sticky="e", padx=(0,12), pady=8)
            
            # Time selection with popup button
            time_frame = tk.Frame(inner)
            time_frame.grid(row=8, column=1, sticky="w", padx=(0,12), pady=8)
            
            self.available_time_slots = [True for _ in range(24*7)]  # list to hold available time slots
            self.time_slots = [False for _ in range(24*7)]  # list to hold time slot selections
            self.time_display = tk.Label(time_frame, text="No times selected", anchor="w", width=30, relief="sunken", bd=1)
            self.time_display.pack(side="left", padx=(0, 8))
            
            time_select_btn = tk.Button(time_frame, text="Select Times", command=self.open_new_time_selector)
            time_select_btn.pack(side="left")

            tk.Label(inner, text="Description:", anchor="ne").grid(row=9, column=0, sticky="ne", padx=(0,12), pady=8)
            self.description_entry = tk.Text(
                inner,
                height=10,
                width=50,
                wrap="word",
                relief="sunken",
                bd=1,
                state="disabled",
                bg="lightgray"
            )
            self.description_entry.grid(row=9, column=1, sticky="ew", padx=(0,12), pady=8)

            self.log_label = tk.Label(inner, font=("Helvetica", 12), fg="red", text="")
            self.log_label.grid(row=10, column=0, columnspan=2, sticky="nsew")

            btn_frame = tk.Frame(inner)
            btn_frame.grid(row=11, column=0, columnspan=2, pady=18, sticky="n")
            btn_frame.grid_columnconfigure(0, weight=1)
            btn_frame.grid_columnconfigure(1, weight=1)

            back_btn = tk.Button(btn_frame, text="Back",
                command=self.back)
            take_request_btn = tk.Button(btn_frame, text="Take Request",
                command=self.take_request)
            # place the buttons in the frame so they are used and visible
            back_btn.grid(row=0, column=1, sticky="ew", padx=8)
            take_request_btn.grid(row=0, column=2, sticky="ew", padx=8)
        
        def open_new_time_selector(self):
            """Open popup dialog for time selection"""

            dialog = TimeSelectionDialog(self, self.time_slots, disabled=False, available=self.available_time_slots)
            self.wait_window(dialog)
            self.update_time_display()
            # Update display after dialog closes
        
        '''
        def update_time_display(self):
            """Update the time display label based on selected slots"""
            selected_count = sum(self.time_slots)
            if selected_count == 0:
                self.time_display.config(text="No times selected")
            else:
                self.time_display.config(text=f"{selected_count} time slot(s) selected")
        '''

        def update_time_display(self):
            """Update the time display label based on selected slots"""
            selected_count = sum(self.time_slots)
            available_count = sum(self.available_time_slots)
            if selected_count == 0:
                self.time_display.config(text=f"No times selected / {available_count} available")
            else:
                self.time_display.config(text=f"{selected_count} / {available_count} time slot(s) selected")

        def back(self):
            self.controller.show_frame("SearchRequestResultPage")
        
        def take_request(self):
            time = ''.join(['1' if slot else '0' for slot in self.time_slots])
            for i in range(24*7):
                if self.time_slots[i] and not self.available_time_slots[i]:
                    self.log_message("Selected time slots include unavailable times. Please adjust your selection.")
                    return
                
            if sum(self.time_slots) == 0:
                self.log_message("Please select at least one time slot to take the request.")
                return
            success, msg = BackendAPI.take_request(u_id=self.session.u_id, r_id=self.r_id, time=time)
            if success:
                self.log_message("Request taken successfully.")
                sleep(2)
                self.back()
            else:
                self.log_message(f"Failed to take request: {msg}")

        def log_message(self, message):
            self.log_label.config(text=message)

        def clear_log(self):
            self.log_label.config(text="")

        def switched_to(self, item):
            if item is None:
                print("No item to enter.")
                # clear all fields
                self.r_id = ""
                self.u_id = ""
                self.username_label.config(text="")
                self.real_name_label.config(text="")
                self.time_slots = [False for _ in range(24*7)]
                self.update_time_display()
                for i in range(8):
                    self.gyear_vars[i].set(0)
                self.role_label.config(text="")
                self.subject_label.config(text="")
                self.reward_label.config(text="")
                self.location_label.config(text="")
                self.description_entry.config(state="normal")
                self.description_entry.delete("1.0", tk.END)
                self.description_entry.config(state="disabled")

                return
            # populate fields from item
            r_id = item.get("r_id", "")
            u_id = item.get("u_id", "")
            username = item.get("username", "")
            real_name = item.get("realname", "")
            role = item.get("role", "")
            subject = item.get("subject", "")
            target_gradeyear = item.get("target_gradeyear", "00000000")
            description = item.get("request_detail", "")
            reward = item.get("reward", 0)
            location = item.get("place", "")
            time_slots_str = item.get("time", "0" * 168)
            for i in range(24*7):
                self.available_time_slots[i] = (time_slots_str[i] == '1')
                self.time_slots[i] = False  # reset selected slots
            self.update_time_display()
            self.clear_log()
            self.r_id = r_id
            self.u_id = u_id
            self.username_label.config(text=username)
            self.real_name_label.config(text=real_name)
            for i in range(8):
                if target_gradeyear[i] == '1':
                    self.gyear_vars[i].set(1)
                else:
                    self.gyear_vars[i].set(0)
            self.role_label.config(text=role)
            self.subject_label.config(text=subject)
            self.reward_label.config(text=str(reward))
            self.location_label.config(text=location)
            self.description_entry.config(state="normal")
            self.description_entry.delete("1.0", tk.END)
            self.description_entry.insert("1.0", description)
            self.description_entry.config(state="disabled")
    
    class ViewTakeResultPage(tk.Frame):
        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.from_page = ""
            self.controller = controller
            self.session = session

            label = tk.Label(self, text="Taken Request Result Page", font=("Helvetica", 20))
            label.pack(pady=10, padx=10)

            # scrollable listbox you can append items to
            list_frame = tk.Frame(self)
            list_frame.pack(fill="both", expand=True, padx=10, pady=10)

            scrollbar = tk.Scrollbar(list_frame, orient="vertical")
            scrollbar.pack(side="right", fill="y")

            # use single selection so clicks map cleanly to one item
            self.result_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, selectmode="browse")
            self.result_listbox.pack(side="left", fill="both", expand=True)

            scrollbar.config(command=self.result_listbox.yview)

            # bind double-click and Enter to activate item
            self.result_listbox.bind("<Double-Button-1>", lambda e: self._on_item_activate())
            self.result_listbox.bind("<Return>", lambda e: self._on_item_activate())

            # log label
            self.log_label = tk.Label(self, font=("Helvetica", 12), fg="red", text="")
            self.log_label.pack(pady=5)

            # back button
            back_button = tk.Button(self, text="Back",
                                command=self.go_back)
            back_button.pack(pady=10)

        def append_item(self, item=None):
            """
            Append an item to the listbox. Optionally provide a callback
            function that will be called when the item is activated.
            The callback receives (text, index).
            """
            if item is None:
                text = "No takes found."
            else:
                text = f"{item['taker_username']} | {item['subject']} | {item['gradeyear_display']} | {item['time_ranges']}"
            self.result_listbox.insert(tk.END, text)
            # keep the newest item visible
            self.result_listbox.see(tk.END)

        def _on_item_activate(self):
            selection = self.result_listbox.curselection()
            if not selection:
                return
            idx = selection[0] # get the selected index
            item_text = self.result_listbox.get(idx)
            callback = self.enter_item(self.items[idx])
            if callback:
                callback(item_text, idx)

        def clear_items(self):
            self.result_listbox.delete(0, tk.END)
        
        def load_items(self, items):
            self.items = items
            self.clear_items()
            for item in items:
                self.append_item(item)

        def enter_item(self, item):
            if item is None:
                print("No item to enter.")
                return
            self.controller.frames["TakeDetailPage"].switched_to(item)
            self.controller.show_frame("TakeDetailPage")

        def go_back(self):
            if self.from_page == "EditRequestPage":
                self.controller.show_frame("EditRequestPage")
            else:
                self.controller.frames["UserPage"].switched_to()
                self.controller.show_frame("UserPage")

        def switched_to(self, items=None, from_page="UserPage"):
            self.from_page = from_page
            if not items:
                self.clear_items()
                self.append_item(None)
                self.items = []
                return
            self.load_items(items)
            self.items = items
        
        def log_message(self, message):
            self.log_label.config(text=message)
        
        def clear_log(self):
            self.log_label.config(text="")
    
    class TakeDetailPage(tk.Frame):
        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.controller = controller
            self.session = session
            self.item = None
            
            # allow this page to expand to fill the 800x600 container
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)

            inner = tk.Frame(self, bd=8)
            inner.grid(row=0, column=0, sticky="nsew", padx=40, pady=20)

            # Add more widgets for posting requests here
            inner.grid_columnconfigure(0, weight=0)   # labels
            inner.grid_columnconfigure(1, weight=1)   # entry widgets expand
            inner.grid_rowconfigure(0, weight=0)
            inner.grid_rowconfigure(1, weight=0)
            inner.grid_rowconfigure(2, weight=0)
            inner.grid_rowconfigure(3, weight=0)
            inner.grid_rowconfigure(4, weight=0)
            inner.grid_rowconfigure(5, weight=0)
            inner.grid_rowconfigure(6, weight=0)
            inner.grid_rowconfigure(7, weight=0)
            inner.grid_rowconfigure(8, weight=0)
            inner.grid_rowconfigure(9, weight=0)
            inner.grid_rowconfigure(10, weight=0)  # log label
            inner.grid_rowconfigure(11, weight=0)  # buttons

            row = 0

            label = tk.Label(inner, text="Take Detail Page", font=("Helvetica", 20))
            label.grid(row=row, column=0, columnspan=2, pady=(0, 16))

            row += 1
            tk.Label(inner, text="Your username:", anchor="e").grid(row=row, column=0, sticky="e", padx=(0,12), pady=8)
            self.username_label = tk.Label(inner, text="", anchor="w")
            self.username_label.grid(row=row, column=1, sticky="w", padx=(0,12), pady=8)

            row += 1
            tk.Label(inner, text="Your Role:", anchor="e").grid(row=row, column=0, sticky="e", padx=(0,12), pady=8)
            self.role_label = tk.Label(inner, text="", anchor="w")
            self.role_label.grid(row=row, column=1, sticky="w", padx=(0,12), pady=8)

            row += 1
            tk.Label(inner, text="Taker username:", anchor="e").grid(row=row, column=0, sticky="e", padx=(0,12), pady=8)
            self.taker_username_label = tk.Label(inner, text="", anchor="w")
            self.taker_username_label.grid(row=row, column=1, sticky="w", padx=(0,12), pady=8)

            row += 1
            tk.Label(inner, text="Taker realname:", anchor="e").grid(row=row, column=0, sticky="e", padx=(0,12), pady=8)
            self.taker_realname_label = tk.Label(inner, text="", anchor="w")
            self.taker_realname_label.grid(row=row, column=1, sticky="w", padx=(0,12), pady=8)

            row += 1
            tk.Label(inner, text="Taker email:", anchor="e").grid(row=row, column=0, sticky="e", padx=(0,12), pady=8)
            self.taker_email_label = tk.Label(inner, text="", anchor="w")
            self.taker_email_label.grid(row=row, column=1, sticky="w", padx=(0,12), pady=8)

            row += 1
            tk.Label(inner, text="Subject:", anchor="e").grid(row=row, column=0, sticky="e", padx=(0,12), pady=8)
            self.subject_label = tk.Label(inner, text="", anchor="w")
            self.subject_label.grid(row=row, column=1, sticky="w", padx=(0,12), pady=8)

            row += 1
            tk.Label(inner, text="Time:", anchor="e").grid(row=row, column=0, sticky="e", padx=(0,12), pady=8)
            
            # Time selection with popup button
            time_frame = tk.Frame(inner)
            time_frame.grid(row=row, column=1, sticky="w", padx=(0,12), pady=8)
            
            self.available_time_slots = [True for _ in range(24*7)]  # list to hold available time slots
            self.time_slots = [False for _ in range(24*7)]  # list to hold time slot selections
            self.time_display = tk.Label(time_frame, text="No times selected", anchor="w", width=30, relief="sunken", bd=1)
            self.time_display.pack(side="left", padx=(0, 8))
            
            time_select_btn = tk.Button(time_frame, text="View Times", command=self.open_new_time_selector)
            time_select_btn.pack(side="left")

            row += 1
            tk.Label(inner, text="Reward (NT$/hr):", anchor="e").grid(row=row, column=0, sticky="e", padx=(0,12), pady=8)
            self.reward_label = tk.Label(inner, text="", anchor="w")
            self.reward_label.grid(row=row, column=1, sticky="w", padx=(0,12), pady=8)

            row += 1
            tk.Label(inner, text="Location:", anchor="e").grid(row=row, column=0, sticky="e", padx=(0,12), pady=8)
            self.location_label = tk.Label(inner, text="", anchor="w")
            self.location_label.grid(row=row, column=1, sticky="w", padx=(0,12), pady=8)
                        

            self.log_label = tk.Label(inner, font=("Helvetica", 12), fg="red", text="")
            self.log_label.grid(row=row+1, column=0, columnspan=2, sticky="nsew")
            btn_frame = tk.Frame(inner)
            btn_frame.grid(row=row+2, column=0, columnspan=2, pady=18, sticky="n")
            btn_frame.grid_columnconfigure(0, weight=1)
            btn_frame.grid_columnconfigure(1, weight=1)
            btn_frame.grid_columnconfigure(2, weight=1)

            post_btn = tk.Button(btn_frame, text="Confirm Take",
                command=self.confirm_take)
            cancel_btn = tk.Button(btn_frame, text="Decline Take",
                command=self.decline_take)
            view_takes_btn = tk.Button(btn_frame, text="Back to Takes",
                command=self.back_to_takes)
            # place the buttons in the frame so they are used and visible
            post_btn.grid(row=0, column=0, sticky="ew", padx=8)
            cancel_btn.grid(row=0, column=1, sticky="ew", padx=8)
            view_takes_btn.grid(row=0, column=2, sticky="ew", padx=8)

        def open_new_time_selector(self):
            """Open popup dialog for time selection"""
            
            dialog = TimeSelectionDialog(self, self.time_slots, disabled=True)
            self.wait_window(dialog)
            # Update display after dialog closes
            # Only for showing selected times, not editing, so no need to update self.time_slots
            # self.update_time_display()
        
    
        def update_time_display(self):
            """Update the time display label based on selected slots"""
            selected_count = sum(self.time_slots)
            if selected_count == 0:
                self.time_display.config(text="No times selected")
            else:
                self.time_display.config(text=f"{selected_count} time slot(s) selected")

        def decline_take(self):
            if self.item is None:
                self.log_message("No item selected to decline.")
                return
            taker_uid = self.item.get("taker_uid", "")
            r_id = self.item.get("r_id", "")
            owner_uid = self.item.get("owner_uid", "")

            success, msg = BackendAPI.deny_applicant(taker_uid, r_id, owner_uid)

            if not success:
                self.log_message(f"Failed to decline take: {msg}")
                return
            
            self.log_message("Take declined successfully.")
            sleep(2)
            self.controller.show_frame("UserPage")

        def confirm_take(self):
            if self.item is None:
                self.log_message("No item selected to decline.")
                return
            taker_uid = self.item.get("taker_uid", "")
            r_id = self.item.get("r_id", "")
            owner_uid = self.item.get("owner_uid", "")

            success, msg, course_id = BackendAPI.confirm_applicant(taker_uid, r_id, owner_uid)

            if not success:
                self.log_message(f"Failed to confirm take: {msg}")
                return
            
            self.log_message(f"Take confirmed. Course #{course_id} created.")
            sleep(2)
            self.controller.show_frame("UserPage")
        
        def back_to_takes(self):
            self.controller.show_frame("ViewTakeResultPage")

        def log_message(self, message):
            self.log_label.config(text=message)

        def clear_log(self):
            self.log_label.config(text="")

        def switched_to(self, item):
            self.item = item
            '''
            results.append({
                    "taker_uid": taker_uid,
                    "taker_username": taker_username,
                    "taker_realname": taker_realname,
                    "taker_email": taker_email,
                    "time": take_time,
                    "time_ranges": convert_168bit_to_ranges(take_time),
                    "r_id": r_id,
                    "owner_uid": owner_uid,
                    "role": role,
                    "target_gradeyear": grade_bits,
                    "gradeyear_display": convert_grade_bits(grade_bits),
                    "subject": subject,
                    "request_detail": detail,
                    "reward": reward,
                    "place": place
                })
            '''

            if item is None:
                print("No item to enter.")
                # clear all fields
                self.username_label.config(text="")
                self.role_label.config(text="")
                self.taker_username_label.config(text="")
                self.taker_realname_label.config(text="")
                self.taker_email_label.config(text="")
                self.subject_label.config(text="")
                self.reward_label.config(text="")
                self.location_label.config(text="")
                self.time_slots = [False for _ in range(24*7)]
                self.update_time_display()
                return
            # populate fields from item
            assert item.get("owner_uid", "") == self.session.u_id, "Owner UID does not match session UID."
            taker_username = item.get("taker_username", "")
            taker_realname = item.get("taker_realname", "")
            taker_email = item.get("taker_email", "")
            subject = item.get("subject", "")
            reward = item.get("reward", 0)
            role = item.get("role", "")
            location = item.get("place", "")
            time_slots_str = item.get("time", "0" * 168)
            for i in range(24*7):
                self.time_slots[i] = (time_slots_str[i] == '1')
            self.update_time_display()
            self.clear_log()
            self.username_label.config(text=self.session.username)
            self.role_label.config(text=role)
            self.taker_username_label.config(text=taker_username)
            self.taker_realname_label.config(text=taker_realname)
            self.taker_email_label.config(text=taker_email)
            self.subject_label.config(text=subject)
            self.reward_label.config(text=str(reward))
            self.location_label.config(text=location)

    class MyCoursesPage(tk.Frame):
        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.controller = controller
            self.session = session

            label = tk.Label(self, text="My Courses Page", font=("Helvetica", 20))
            label.pack(pady=10, padx=10)

            # scrollable listbox you can append items to
            list_frame = tk.Frame(self)
            list_frame.pack(fill="both", expand=True, padx=10, pady=10)

            scrollbar = tk.Scrollbar(list_frame, orient="vertical")
            scrollbar.pack(side="right", fill="y")

            # use single selection so clicks map cleanly to one item
            self.result_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, selectmode="browse")
            self.result_listbox.pack(side="left", fill="both", expand=True)

            scrollbar.config(command=self.result_listbox.yview)

            # bind double-click and Enter to activate item
            self.result_listbox.bind("<Double-Button-1>", lambda e: self._on_item_activate())
            self.result_listbox.bind("<Return>", lambda e: self._on_item_activate())

            # log label
            self.log_label = tk.Label(self, font=("Helvetica", 12), fg="red", text="")
            self.log_label.pack(pady=5)

            # back button
            back_button = tk.Button(self, text="Back",
                                command=self.go_back)
            back_button.pack(pady=10)

        def append_item(self, item=None):
            """
            Append an item to the listbox. Optionally provide a callback
            function that will be called when the item is activated.
            The callback receives (text, index).
            """
            if item is None:
                text = "No courses found."
            else:
                text = f"#{item['c_id']} | {item['subject']} | {item['time_ranges']} | {item['place']}"
            self.result_listbox.insert(tk.END, text)
            # keep the newest item visible
            self.result_listbox.see(tk.END)

        def _on_item_activate(self):
            selection = self.result_listbox.curselection()
            if not selection:
                return
            idx = selection[0] # get the selected index
            item_text = self.result_listbox.get(idx)
            callback = self.enter_item(self.items[idx])
            if callback:
                callback(item_text, idx)

        def clear_items(self):
            self.result_listbox.delete(0, tk.END)
        
        def load_items(self, items):
            self.items = items
            self.clear_items()
            for item in items:
                self.append_item(item)

        def enter_item(self, item):
            if item is None:
                print("No item to enter.")
                return
            self.controller.frames["CourseDetailPage"].switched_to(item)
            self.controller.show_frame("CourseDetailPage")

        def go_back(self):
            self.controller.frames["UserPage"].switched_to()
            self.controller.show_frame("UserPage")

        def switched_to(self, items=None):
                       
            if not items:
                self.clear_items()
                self.append_item(None)
                self.items = []
                return
            self.load_items(items)
            self.items = items
        
        def log_message(self, message):
            self.log_label.config(text=message)
        
        def clear_log(self):
            self.log_label.config(text="")

    class CourseDetailPage(tk.Frame):
        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.controller = controller
            self.session = session
            self.item = None
            
            # allow this page to expand to fill the 800x600 container
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)

            inner = tk.Frame(self, bd=8)
            inner.grid(row=0, column=0, sticky="nsew", padx=40, pady=20)

            # Add more widgets for posting requests here
            inner.grid_columnconfigure(0, weight=0)   # labels
            inner.grid_columnconfigure(1, weight=1)   # entry widgets expand
            inner.grid_rowconfigure(0, weight=0)
            inner.grid_rowconfigure(1, weight=0)
            inner.grid_rowconfigure(2, weight=0)
            inner.grid_rowconfigure(3, weight=0)
            inner.grid_rowconfigure(4, weight=0)
            inner.grid_rowconfigure(5, weight=0)
            inner.grid_rowconfigure(6, weight=0)
            inner.grid_rowconfigure(7, weight=0)
            inner.grid_rowconfigure(8, weight=0)
            inner.grid_rowconfigure(9, weight=0)
            inner.grid_rowconfigure(10, weight=0)  
            inner.grid_rowconfigure(11, weight=0)  # log label
            inner.grid_rowconfigure(12, weight=0)  # buttons

            row = 0

            label = tk.Label(inner, text="Course Detail Page", font=("Helvetica", 20))
            label.grid(row=row, column=0, columnspan=2, pady=(0, 16))

            row += 1
            tk.Label(inner, text="Teacher:", anchor="e").grid(row=row, column=0, sticky="e", padx=(0,12), pady=8)
            self.teacher_label = tk.Label(inner, text="", anchor="w")
            self.teacher_label.grid(row=row, column=1, sticky="w", padx=(0,12), pady=8)

            row += 1
            tk.Label(inner, text="Teacher Rating:", anchor="e").grid(row=row, column=0, sticky="e", padx=(0,12), pady=8)
            self.teacher_rating_var = tk.StringVar(value="None")
            self.teacher_rating_menu = tk.OptionMenu(inner, self.teacher_rating_var,"None", "1", "2", "3", "4", "5")
            self.teacher_rating_menu.config(state="disabled")
            self.teacher_rating_menu.grid(row=row, column=1, sticky="w", padx=(0,12), pady=8)

            row += 1
            tk.Label(inner, text="Student:", anchor="e").grid(row=row, column=0, sticky="e", padx=(0,12), pady=8)
            self.student_label = tk.Label(inner, text="", anchor="w")
            self.student_label.grid(row=row, column=1, sticky="w", padx=(0,12), pady=8)

            row += 1
            tk.Label(inner, text="Student Rating:", anchor="e").grid(row=row, column=0, sticky="e", padx=(0,12), pady=8)
            self.student_rating_var = tk.StringVar(value="None")
            self.student_rating_menu = tk.OptionMenu(inner, self.student_rating_var,"None", "1", "2", "3", "4", "5")
            self.student_rating_menu.config(state="disabled")
            self.student_rating_menu.grid(row=row, column=1, sticky="w", padx=(0,12), pady=8)

            row += 1
            tk.Label(inner, text="Partner email:", anchor="e").grid(row=row, column=0, sticky="e", padx=(0,12), pady=8)
            self.partner_email_label = tk.Label(inner, text="", anchor="w")
            self.partner_email_label.grid(row=row, column=1, sticky="w", padx=(0,12), pady=8)

            row += 1
            tk.Label(inner, text="Partner Real Name:", anchor="e").grid(row=row, column=0, sticky="e", padx=(0,12), pady=8)
            self.partner_realname_label = tk.Label(inner, text="", anchor="w")
            self.partner_realname_label.grid(row=row, column=1, sticky="w", padx=(0,12), pady=8)

            row += 1
            tk.Label(inner, text="Subject:", anchor="e").grid(row=row, column=0, sticky="e", padx=(0,12), pady=8)
            self.subject_label = tk.Label(inner, text="", anchor="w")
            self.subject_label.grid(row=row, column=1, sticky="w", padx=(0,12), pady=8)

            row += 1
            tk.Label(inner, text="Time:", anchor="e").grid(row=row, column=0, sticky="e", padx=(0,12), pady=8)
            
            # Time selection with popup button
            time_frame = tk.Frame(inner)
            time_frame.grid(row=row, column=1, sticky="w", padx=(0,12), pady=8)
            
            self.available_time_slots = [True for _ in range(24*7)]  # list to hold available time slots
            self.time_slots = [False for _ in range(24*7)]  # list to hold time slot selections
            self.time_display = tk.Label(time_frame, text="No times selected", anchor="w", width=30, relief="sunken", bd=1)
            self.time_display.pack(side="left", padx=(0, 8))
            
            time_select_btn = tk.Button(time_frame, text="View Times", command=self.open_new_time_selector)
            time_select_btn.pack(side="left")

            row += 1
            tk.Label(inner, text="Reward (NT$/hr):", anchor="e").grid(row=row, column=0, sticky="e", padx=(0,12), pady=8)
            self.reward_label = tk.Label(inner, text="", anchor="w")
            self.reward_label.grid(row=row, column=1, sticky="w", padx=(0,12), pady=8)

            row += 1
            tk.Label(inner, text="Location:", anchor="e").grid(row=row, column=0, sticky="e", padx=(0,12), pady=8)
            self.location_label = tk.Label(inner, text="", anchor="w")
            self.location_label.grid(row=row, column=1, sticky="w", padx=(0,12), pady=8)
                        

            self.log_label = tk.Label(inner, font=("Helvetica", 12), fg="red", text="")
            self.log_label.grid(row=row+1, column=0, columnspan=2, sticky="nsew")
            btn_frame = tk.Frame(inner)

            btn_frame.grid(row=row+2, column=0, columnspan=2, pady=18, sticky="n")
            btn_frame.grid_columnconfigure(0, weight=1)
            btn_frame.grid_columnconfigure(1, weight=1)

            post_btn = tk.Button(btn_frame, text="Back to Courses",
                command=self.back_to_courses)
            cancel_btn = tk.Button(btn_frame, text="Update Ratings",
                command=self.update_ratings)
            # place the buttons in the frame so they are used and visible
            post_btn.grid(row=0, column=0, sticky="ew", padx=8)
            cancel_btn.grid(row=0, column=1, sticky="ew", padx=8)

        def open_new_time_selector(self):
            """Open popup dialog for time selection"""
            
            dialog = TimeSelectionDialog(self, self.time_slots, disabled=True)
            self.wait_window(dialog)
            # Update display after dialog closes
            # Only for showing selected times, not editing, so no need to update self.time_slots
            # self.update_time_display()
        
    
        def update_time_display(self, txt=None):
            """Update the time display label based on selected slots"""
            selected_count = sum(self.time_slots)
            if selected_count == 0:
                self.time_display.config(text=txt or "No times selected")
            else:
                self.time_display.config(text=txt or f"{selected_count} time slot(s) selected")

        def back_to_courses(self):
            self.controller.show_frame("MyCoursesPage")

        def update_ratings(self):
            if self.item is None:
                self.log_message("No item selected to update.")
                return
            c_id = self.item.get("c_id", "")
            role = self.item.get("role", "")
            if role == "teacher":
                #  def rate_course(u_id, c_id, score):
                score_str = self.student_rating_var.get()
                if score_str == "None":
                    self.log_message("No student rating selected.")
                    return
                score = int(score_str)
                success, msg = BackendAPI.rate_course(self.session.u_id, c_id, score)
                if not success:
                    self.log_message(f"Failed to update student rating: {msg}")
                    return
                self.log_message("Student rating updated successfully.")
            else:
                score_str = self.teacher_rating_var.get()
                if score_str == "None":
                    self.log_message("No teacher rating selected.")
                    return
                score = int(score_str)
                success, msg = BackendAPI.rate_course(self.session.u_id, c_id, score)
                if not success:
                    self.log_message(f"Failed to update teacher rating: {msg}")
                    return
                self.log_message("Teacher rating updated successfully.")
            

        def log_message(self, message):
            self.log_label.config(text=message)

        def clear_log(self):
            self.log_label.config(text="")

        def switched_to(self, item):
            self.item = item
            '''
            student_courses.append({
                    "c_id": c_id,
                    "student_u_id": student_uid,
                    "teacher_u_id": teacher_uid,
                    "partner_username": username,
                    "partner_realname": realname,
                    "partner_email": email,
                    "time": take_time,
                    "time_ranges": time_str if isinstance(time_str, list) else [],
                    "target_gradeyear": grade_bits,
                    "gradeyear_display": convert_grade_bits(grade_bits),
                    "subject": subject,
                    "request_detail": detail,
                    "reward": reward,
                    "place": place,
                    "student_score": student_score,
                    "teacher_score": teacher_score,
                    "role": "student"
                })
            '''
            if item is None:
                print("No item to enter.")
                # clear all fields
                self.teacher_label.config(text="")
                self.student_label.config(text="")
                self.partner_email_label.config(text="")
                self.partner_realname_label.config(text="")
                self.subject_label.config(text="")
                self.reward_label.config(text="")
                self.location_label.config(text="")
                self.time_slots = [False for _ in range(24*7)]
                self.update_time_display()
                self.teacher_rating_var.set("None")
                self.teacher_rating_menu.config(state="disabled")
                self.student_rating_var.set("None")
                self.student_rating_menu.config(state="disabled")
                return
            # populate fields from item
            role = item.get("role", "")
            if role == "teacher":
                partner_name = item.get("partner_username", "")
                partner_realname = item.get("partner_realname", "")
                partner_email = item.get("partner_email", "")
                self.teacher_label.config(text=self.session.username)
                self.student_label.config(text=partner_name)
                self.partner_email_label.config(text=partner_email)
                self.partner_realname_label.config(text=partner_realname)
                self.teacher_rating_var.set(str(item.get("teacher_score", "None")))
                self.teacher_rating_menu.config(state="disabled")
                self.student_rating_var.set(str(item.get("student_score", "None")))
                self.student_rating_menu.config(state="normal")
            else:
                partner_name = item.get("partner_username", "")
                partner_realname = item.get("partner_realname", "")
                partner_email = item.get("partner_email", "")
                self.student_label.config(text=self.session.username)
                self.teacher_label.config(text=partner_name)
                self.partner_email_label.config(text=partner_email)
                self.partner_realname_label.config(text=partner_realname)
                self.teacher_rating_var.set(str(item.get("teacher_score", "None")))
                self.teacher_rating_menu.config(state="normal")
                self.student_rating_var.set(str(item.get("student_score", "None")))
                self.student_rating_menu.config(state="disabled")
            subject = item.get("subject", "")
            reward = item.get("reward", 0)
            location = item.get("place", "")
            time_slots_str = item.get("time", "0" * 168)
            for i in range(24*7):
                self.time_slots[i] = (time_slots_str[i] == '1')
            self.update_time_display(item.get("time_ranges", ""))
            self.clear_log()
            self.subject_label.config(text=subject)
            self.reward_label.config(text=str(reward))
            self.location_label.config(text=location)   
            
    class AdminPage(tk.Frame):
        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.session = session
            
            # allow this page to expand to fill the 800x600 container
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)
            self.controller = controller


            inner = tk.Frame(self, bd=8)
            inner.grid(row=0, column=0, sticky="nsew", padx=40, pady=20)


            label = tk.Label(inner, text="Admin Page", font=("Helvetica", 20))
            label.pack(pady=10, padx=10)

            btn_frame = tk.Frame(inner)
            btn_frame.pack(pady=10, padx=40, fill="x")

            search_user_button = tk.Button(btn_frame, text="Search User",
                                    command=self.search_user)
            search_user_button.pack(fill="x", pady=4)

            search_request_button = tk.Button(btn_frame, text="Search Request",
                                     command=self.search_request)
            search_request_button.pack(fill="x", pady=4)

            search_takes_button = tk.Button(btn_frame, text="Search Takes",
                                 command=self.search_takes)
            search_takes_button.pack(fill="x", pady=4)

            search_courses_button = tk.Button(btn_frame, text="Search Courses",
                                  command=self.search_courses)
            search_courses_button.pack(fill="x", pady=4)

            logout_button = tk.Button(btn_frame, text="Logout",
                                 command=self.logout)
            logout_button.pack(fill="x", pady=4)

            self.log_label = tk.Label(inner, font=("Helvetica", 12), fg="red", text="")
            self.log_label.pack(fill="x", pady=4)
        
        def search_user(self):
            self.controller.frames["AdminSearchUserPage"].switched_to()
            self.controller.show_frame("AdminSearchUserPage")

        def search_request(self):
            self.controller.frames["AdminSearchRequestPage"].switched_to(clear=True)
            self.controller.show_frame("AdminSearchRequestPage")

        def search_takes(self):
            self.controller.frames["AdminSearchTakePage"].switched_to(clear=True)
            self.controller.show_frame("AdminSearchTakePage")

        def search_courses(self):
            self.controller.frames["AdminSearchCoursePage"].switched_to(clear=True)
            self.controller.show_frame("AdminSearchCoursePage")

        def logout(self):

            self.session.logout()
            self.controller.frames["LoginPage"].switched_to()
            self.controller.show_frame("LoginPage")
    
        def log_message(self, message):
            self.log_label.config(text=message, fg="red")

        def clear_log(self):
            self.log_label.config(text="")

        def switched_to(self):
            self.clear_log()
        
    class AdminSearchUserPage(tk.Frame):

        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.controller = controller
            self.session = session
        # allow this page to expand to fill the 800x600 container
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)

            inner = tk.Frame(self, bd=8)
            inner.grid(row=0, column=0, sticky="nsew", padx=40, pady=20)

            # Add more widgets for posting requests here
            inner.grid_columnconfigure(0, weight=0)   # labels
            inner.grid_columnconfigure(1, weight=1)   # entry widgets expand
            inner.grid_rowconfigure(0, weight=0)
            inner.grid_rowconfigure(1, weight=0)
            inner.grid_rowconfigure(2, weight=0)
            inner.grid_rowconfigure(3, weight=0)


            label = tk.Label(inner, text="Admin Search User Page", font=("Helvetica", 20))
            label.grid(row=0, column=0, columnspan=2, pady=(0, 16))

            tk.Label(inner, text="User id:", anchor="e").grid(row=1, column=0, sticky="e", padx=(0,12), pady=8)
            self.user_id_entry = tk.Entry(inner, text="")
            self.user_id_entry.grid(row=1, column=1, sticky="w", padx=(0,12), pady=8)

            self.log_label = tk.Label(inner, font=("Helvetica", 12), fg="red", text="")
            self.log_label.grid(row=2, column=0, columnspan=2, sticky="nsew")

            btn_frame = tk.Frame(inner)
            btn_frame.grid(row=3, column=0, columnspan=2, pady=18, sticky="n")
            btn_frame.grid_columnconfigure(0, weight=1)
            btn_frame.grid_columnconfigure(1, weight=1)

            search_btn = tk.Button(btn_frame, text="Search",
                command=self.search_user)
            back_btn = tk.Button(btn_frame, text="Back",
                 command=self.back)
            # place the buttons in the frame so they are used and visible
            search_btn.grid(row=0, column=0, sticky="ew", padx=8)
            back_btn.grid(row=0, column=1, sticky="ew", padx=8)

        def search_user(self):
            admin_uid = self.session.u_id
            user_id = self.user_id_entry.get().strip()
            if not user_id:
                self.log_message("User id cannot be empty.")
                return
            success, msg, user_info = BackendAPI.admin_search_user(admin_uid, user_id)
            if not success:
                self.log_message(f"Search failed: {msg}")
                return
            # show user detail page
            self.controller.frames["AdminUserDetailPage"].switched_to(user_info)
            self.controller.show_frame("AdminUserDetailPage")

        def back(self):
            self.controller.frames["AdminPage"].switched_to()
            self.controller.show_frame("AdminPage")

        def log_message(self, message):
            self.log_label.config(text=message)
        def clear_log(self):
            self.log_label.config(text="")
        def switched_to(self):
            self.user_id_entry.delete(0, tk.END)
            self.clear_log()
    
    class AdminUserDetailPage(tk.Frame):
        
        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.controller = controller
            self.session = session
            self.user_info = None
            self.reset_password_warning_issued = False
            self.change_role_warning_issued = False
            self.suspend_warning_issued = False
        # allow this page to expand to fill the 800x600 container
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)

            inner = tk.Frame(self, bd=8)
            inner.grid(row=0, column=0, sticky="nsew", padx=40, pady=20)

            '''
            return (True, "查詢成功", {
                "u_id": u_id_val,
                "username": username,
                "realname": realname,
                "email": email,
                "role": role,
                "status": status
            })'''
            # Add more widgets for posting requests here
            inner.grid_columnconfigure(0, weight=0)   # labels
            inner.grid_columnconfigure(1, weight=1)   # entry widgets expand
            inner.grid_columnconfigure(2, weight=0)   # entry buttons expand
            inner.grid_rowconfigure(0, weight=0)
            inner.grid_rowconfigure(1, weight=0)
            inner.grid_rowconfigure(2, weight=0)
            inner.grid_rowconfigure(3, weight=0)
            inner.grid_rowconfigure(4, weight=0)
            inner.grid_rowconfigure(5, weight=0)
            inner.grid_rowconfigure(6, weight=0)
            inner.grid_rowconfigure(7, weight=0)
            inner.grid_rowconfigure(8, weight=0)  # log label
            inner.grid_rowconfigure(9, weight=0)  # buttons


            label = tk.Label(inner, text="Admin User Detail Page", font=("Helvetica", 20))
            label.grid(row=0, column=0, columnspan=3, pady=(0, 16))

            tk.Label(inner, text="User id:", anchor="e").grid(row=1, column=0, sticky="e", padx=(0,12), pady=8)
            self.user_id_label = tk.Label(inner, text="", anchor="w")
            self.user_id_label.grid(row=1, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Username:", anchor="e").grid(row=2, column=0, sticky="e", padx=(0,12), pady=8)
            self.username_label = tk.Label(inner, text="", anchor="w")
            self.username_label.grid(row=2, column=1, columnspan=2, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Real Name:", anchor="e").grid(row=3, column=0, sticky="e", padx=(0,12), pady=8)
            self.realname_label = tk.Label(inner, text="", anchor="w")
            self.realname_label.grid(row=3, column=1, columnspan=2, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Email:", anchor="e").grid(row=4, column=0, sticky="e", padx=(0,12), pady=8)
            self.email_label = tk.Label(inner, text="", anchor="w")
            self.email_label.grid(row=4, column=1, columnspan=2, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="New Password:", anchor="e").grid(row=5, column=0, sticky="e", padx=(0,12), pady=8)
            self.new_password_entry = tk.Entry(inner, text="")  # show password entry as normal text
            self.new_password_entry.grid(row=5, column=1, sticky="w", padx=(0,12), pady=8)
            self.reset_password_btn = tk.Button(inner, text="Reset Password",
                command=self.reset_password)
            self.reset_password_btn.grid(row=5, column=2, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Role:", anchor="e").grid(row=6, column=0, sticky="e", padx=(0,12), pady=8)
            self.role_var = tk.StringVar(value="user")
            self.role_menu = tk.OptionMenu(inner, self.role_var, "admin", "user")
            self.role_menu.grid(row=6, column=1, sticky="w", padx=(0,12), pady=8)
            self.change_role_btn = tk.Button(inner, text="Change Role",
                command=self.change_role)
            self.change_role_btn.grid(row=6, column=2, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Status:", anchor="e").grid(row=7, column=0, sticky="e", padx=(0,12), pady=8)
            self.status_label = tk.Label(inner, text="", anchor="w")
            self.status_label.grid(row=7, column=1, sticky="w", padx=(0,12), pady=8)
            self.suspend_btn = tk.Button(inner, text="Suspend User",
                command=self.suspend_user)
            self.suspend_btn.grid(row=7, column=2, sticky="w", padx=(0,12), pady=8)

            self.log_label = tk.Label(inner, font=("Helvetica", 12), fg="red", text="")
            self.log_label.grid(row=8, column=0, columnspan=3, sticky="nsew")

            btn_frame = tk.Frame(inner)
            btn_frame.grid(row=9, column=0, columnspan=3, pady=18, sticky="n")
            btn_frame.grid_columnconfigure(0, weight=1)

            back_btn = tk.Button(btn_frame, text="Back",
                 command=self.back)
            back_btn.grid(row=0, column=0, sticky="ew", padx=8)
            
        def reset_warnings(self):
            self.reset_password_warning_issued = False
            self.change_role_warning_issued = False
            self.suspend_warning_issued = False
            

        def back(self):
            self.controller.frames["AdminSearchUserPage"].switched_to()
            self.controller.show_frame("AdminSearchUserPage")
        
        def reset_password(self):
            if self.change_role_warning_issued or self.suspend_warning_issued:
                self.log_message("operation cancelled")
                self.reset_warnings()
                return
            
            admin_uid = self.session.u_id
            if not self.user_info:
                self.log_message("No user info loaded.")
                return
            target_uid = self.user_info.get("u_id", "")
            new_password = self.new_password_entry.get() # no stripping to allow spaces
            if not new_password:
                self.log_message("New password cannot be empty.")
                return
            
            if not self.reset_password_warning_issued:
                if admin_uid == target_uid:
                    self.log_message("Warning: You are about to reset YOUR OWN PASSWORD! Click 'Reset Password' again to confirm.")
                else:
                    self.log_message("Warning: You are about to reset this user's password! Click 'Reset Password' again to confirm.")            
                self.reset_password_warning_issued = True
                return
            self.reset_warnings()

            success, msg = BackendAPI.admin_edit_user_password(admin_uid, target_uid, new_password)
            if not success:
                self.log_message(f"Password reset failed: {msg}")
                return
            self.log_message("Password reset successfully.")
            self.new_password_entry.delete(0, tk.END)

            # return to login page if resetting own password
            if admin_uid == target_uid:
                self.session.logout()
                self.controller.frames["LoginPage"].switched_to()
                self.controller.show_frame("LoginPage")
            else:
                self.controller.frames["AdminSearchUserPage"].switched_to()
                self.controller.show_frame("AdminSearchUserPage")

        def change_role(self):
            if self.reset_password_warning_issued or self.suspend_warning_issued:
                self.log_message("operation cancelled")
                self.reset_warnings()
                return

            admin_uid = self.session.u_id
            if not self.user_info:
                self.log_message("No user info loaded.")
                return
            target_uid = self.user_info.get("u_id", "")
            original_role = self.user_info.get("role", "user")
            new_role = self.role_var.get()
            if new_role == original_role:
                self.log_message("New role is the same as the original role.")
                return

            if self.change_role_warning_issued == False:
                if admin_uid == target_uid:
                    self.log_message("Warning: You are about to change YOUR OWN ROLE! Click 'Change Role' again to confirm.")
                else:
                    self.log_message("Warning: You are about to change this user's role! Click 'Change Role' again to confirm.")            
                self.change_role_warning_issued = True
                return

            success, msg = BackendAPI.admin_edit_user_role(admin_uid, target_uid, new_role)
            if not success:
                self.log_message(f"Role change failed: {msg}")
                return
            self.log_message("Role changed successfully.")
            self.reset_warnings()

            # return to login page if changing own role to user
            if admin_uid == target_uid and new_role != "admin":
                self.session.logout()
                self.controller.frames["LoginPage"].switched_to()
                self.controller.show_frame("LoginPage")
            else:
                self.controller.frames["AdminSearchUserPage"].switched_to()
                self.controller.show_frame("AdminSearchUserPage")

        def suspend_user(self):
            if self.change_role_warning_issued or self.reset_password_warning_issued:
                self.log_message("operation cancelled")
                self.reset_warnings()
                return
            
            admin_uid = self.session.u_id
            if not self.user_info:
                self.log_message("No user info loaded.")
                return
            target_uid = self.user_info.get("u_id", "")

            if self.user_info.get("status", "active") == "suspended":
                self.log_message("User is already suspended.")
                return

            if not self.suspend_warning_issued:
                if admin_uid == target_uid:
                    self.log_message("Warning: You are about to suspend YOUR OWN ACCOUNT! Click 'Suspend User' again to confirm.")
                else:
                    self.log_message("Warning: You are about to suspend this user! Click 'Suspend User' again to confirm.")            
                self.suspend_warning_issued = True
                return
            
            success, msg = BackendAPI.admin_suspend_user(admin_uid, target_uid)
            if not success:
                self.log_message(f"User suspension failed: {msg}")
                return
            self.log_message("User suspended successfully.")
            self.reset_warnings()

            # return to login page if suspending self
            if admin_uid == target_uid:
                self.session.logout()
                self.controller.frames["LoginPage"].switched_to()
                self.controller.show_frame("LoginPage")
            else:
                self.controller.frames["AdminSearchUserPage"].switched_to()
                self.controller.show_frame("AdminSearchUserPage")

        def log_message(self, message):
            self.log_label.config(text=message)
        def clear_log(self):
            self.log_label.config(text="")
        def switched_to(self, user_info):
            if user_info is None:
                print("No user info to enter.")
                return
            self.user_info = user_info
            self.user_id_label.config(text=user_info.get("u_id", ""))
            self.username_label.config(text=user_info.get("username", ""))
            self.realname_label.config(text=user_info.get("realname", ""))
            self.email_label.config(text=user_info.get("email", ""))
            self.role_var.set(user_info.get("role", "user"))
            self.status_label.config(text=user_info.get("status", "active"))
            self.new_password_entry.delete(0, tk.END)
            self.clear_log()
            
    class AdminSearchRequestPage(tk.Frame):
        
        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.controller = controller
            self.session = session
        # allow this page to expand to fill the 800x600 container
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)

            inner = tk.Frame(self, bd=8)
            inner.grid(row=0, column=0, sticky="nsew", padx=40, pady=20)

            # Add more widgets for posting requests here
            inner.grid_columnconfigure(0, weight=0)   # labels
            inner.grid_columnconfigure(1, weight=1)   # entry widgets expand
            inner.grid_rowconfigure(0, weight=0)
            inner.grid_rowconfigure(1, weight=0)
            inner.grid_rowconfigure(2, weight=0)
            inner.grid_rowconfigure(3, weight=0)
            inner.grid_rowconfigure(4, weight=0)


            label = tk.Label(inner, text="Admin Search Request Page", font=("Helvetica", 20))
            label.grid(row=0, column=0, columnspan=2, pady=(0, 16))

            tk.Label(inner, text="Request Id:", anchor="e").grid(row=1, column=0, sticky="e", padx=(0,12), pady=8)
            self.r_id_entry = tk.Entry(inner, text="")
            self.r_id_entry.grid(row=1, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="User Id:", anchor="e").grid(row=2, column=0, sticky="e", padx=(0,12), pady=8)
            self.u_id_entry = tk.Entry(inner, text="")
            self.u_id_entry.grid(row=2, column=1, sticky="w", padx=(0,12), pady=8)

            self.log_label = tk.Label(inner, font=("Helvetica", 12), fg="red", text="")
            self.log_label.grid(row=3, column=0, columnspan=2, sticky="nsew")

            btn_frame = tk.Frame(inner)
            btn_frame.grid(row=4, column=0, columnspan=2, pady=18, sticky="n")
            btn_frame.grid_columnconfigure(0, weight=1)
            btn_frame.grid_columnconfigure(1, weight=1)

            back_btn = tk.Button(btn_frame, text="Back",
                 command=self.back)
            search_btn = tk.Button(btn_frame, text="Search",
                command=self.search_request)
            
            # place the buttons in the frame so they are used and visible
            back_btn.grid(row=0, column=0, sticky="ew", padx=8)
            search_btn.grid(row=0, column=1, sticky="ew", padx=8)

        def search_request(self):
            u_id = self.u_id_entry.get().strip()
            r_id = self.r_id_entry.get().strip()

            if not u_id.isdigit() and u_id != "":
                self.log_message("Invalid User Id.")
                return
            
            if not r_id.isdigit() and r_id != "":
                self.log_message("Invalid Request Id.")
                return

            if not u_id and not r_id:
                self.log_message("Please enter at least one search criterion.")
                return
            
            success, msg, results = BackendAPI.admin_search_requests(
                self.session.u_id, u_id=u_id, r_id=r_id)

            if not success:
                self.log_message(f"Search failed: {msg}")
                return
            
            if not results:
                self.log_message("No matching requests found.")
                return

            if r_id: # since r_id is unique, only one result expected, directly show detail page
                self.controller.frames["AdminEditRequestPage"].switched_to(results[0])
                self.controller.show_frame("AdminEditRequestPage")
                return

            self.controller.frames["AdminSearchRequestResultPage"].switched_to(results)
            self.controller.show_frame("AdminSearchRequestResultPage")
            
        def back(self):
            self.controller.frames["AdminPage"].switched_to()
            self.controller.show_frame("AdminPage")
        
        def log_message(self, message):
            self.log_label.config(text=message)
        def clear_log(self):
            self.log_label.config(text="")
        def switched_to(self, clear=True):
            if clear:
                self.u_id_entry.delete(0, tk.END)
                self.r_id_entry.delete(0, tk.END)
            self.clear_log()

    class AdminSearchRequestResultPage(tk.Frame):
        
        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.controller = controller
            self.session = session

            label = tk.Label(self, text="Admin Search Request Result Page", font=("Helvetica", 20))
            label.pack(pady=10, padx=10)

            # scrollable listbox you can append items to
            list_frame = tk.Frame(self)
            list_frame.pack(fill="both", expand=True, padx=10, pady=10)

            scrollbar = tk.Scrollbar(list_frame, orient="vertical")
            scrollbar.pack(side="right", fill="y")

            # use single selection so clicks map cleanly to one item
            self.result_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, selectmode="browse")
            self.result_listbox.pack(side="left", fill="both", expand=True)

            scrollbar.config(command=self.result_listbox.yview)

            # bind double-click and Enter to activate item
            self.result_listbox.bind("<Double-Button-1>", lambda e: self._on_item_activate())
            self.result_listbox.bind("<Return>", lambda e: self._on_item_activate())

            # log label
            self.log_label = tk.Label(self, font=("Helvetica", 12), fg="red", text="")
            self.log_label.pack(pady=5)

            # back button
            back_button = tk.Button(self, text="Back",
                                command=self.go_back)
            back_button.pack(pady=10)

        def append_item(self, item=None):
            """
            Append an item to the listbox. Optionally provide a callback
            function that will be called when the item is activated.
            The callback receives (text, index).
            """
            if item is None:
                text = "No requests found."
            else:
                text = f"#{item['r_id']} | {item['subject']} | {item['role']} | {item['gradeyear_display']}"
            self.result_listbox.insert(tk.END, text)
            # keep the newest item visible
            self.result_listbox.see(tk.END)

        def _on_item_activate(self):
            selection = self.result_listbox.curselection()
            if not selection:
                return
            idx = selection[0] # get the selected index
            item_text = self.result_listbox.get(idx)
            callback = self.enter_item(self.items[idx])
            if callback:
                callback(item_text, idx)

        def clear_items(self):
            self.result_listbox.delete(0, tk.END)
        
        def load_items(self, items):
            self.items = items
            self.clear_items()
            for item in items:
                self.append_item(item)

        def enter_item(self, item):
            if item is None:
                print("No item to enter.")
                return
            self.controller.frames["AdminEditRequestPage"].switched_to(item)
            self.controller.show_frame("AdminEditRequestPage")

        def go_back(self):
            self.controller.frames["AdminSearchRequestPage"].switched_to(clear=False)
            self.controller.show_frame("AdminSearchRequestPage")

        def switched_to(self, items=None):
            self.clear_items()
            if not items:
                self.clear_items()
                self.append_item(None)
                self.items = []
                return
            self.load_items(items)
            self.items = items
        
        def log_message(self, message):
            self.log_label.config(text=message)
        
        def clear_log(self):
            self.log_label.config(text="")

    class AdminEditRequestPage(tk.Frame):
        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.controller = controller
            self.session = session

            self.delete_confirmation_issued = False
            
            # allow this page to expand to fill the 800x600 container
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)

            inner = tk.Frame(self, bd=8)
            inner.grid(row=0, column=0, sticky="nsew", padx=40, pady=20)
            
            # Add more widgets for posting requests here
            inner.grid_columnconfigure(0, weight=0)   # labels
            inner.grid_columnconfigure(1, weight=1)   # entry widgets expand
            inner.grid_rowconfigure(0, weight=0)
            inner.grid_rowconfigure(1, weight=0)
            inner.grid_rowconfigure(2, weight=0)
            inner.grid_rowconfigure(3, weight=0)
            inner.grid_rowconfigure(4, weight=0)
            inner.grid_rowconfigure(5, weight=0)
            inner.grid_rowconfigure(6, weight=0)
            inner.grid_rowconfigure(7, weight=0)
            inner.grid_rowconfigure(8, weight=0) 
            inner.grid_rowconfigure(9, weight=1) # description expands
            inner.grid_rowconfigure(10, weight=0)
            inner.grid_rowconfigure(11, weight=0) # buttons

            label = tk.Label(inner, text="Admin Edit Request Page", font=("Helvetica", 20))
            label.grid(row=0, column=0, columnspan=2, pady=(0, 16))

            tk.Label(inner, text="User ID:", anchor="e").grid(row=1, column=0, sticky="e", padx=(0,12), pady=8)
            self.u_id_label = tk.Label(inner, text="", anchor="w")
            self.u_id_label.grid(row=1, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Request ID:", anchor="e").grid(row=2, column=0, sticky="e", padx=(0,12), pady=8)
            self.r_id_label = tk.Label(inner, text="", anchor="w")
            self.r_id_label.grid(row=2, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Role:", anchor="e").grid(row=3, column=0, sticky="e", padx=(0,12), pady=8)
            self.role_label = tk.Label(inner, text="", anchor="w")
            self.role_label.grid(row=3, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Subject:", anchor="e").grid(row=4, column=0, sticky="e", padx=(0,12), pady=8)
            self.subject_label = tk.Label(inner, text="", anchor="w")
            self.subject_label.grid(row=4, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Target Gradeyear:", anchor="e").grid(row=5, column=0, sticky="e", padx=(0,12), pady=8)
            gradeyear_frame = tk.Frame(inner)
                # create 8 expandable columns so the checkbuttons are distributed evenly
            for c in range(8):
                gradeyear_frame.grid_columnconfigure(c, weight=1)
            gradeyear_frame.grid(row=5, column=1, sticky="w", padx=(0,12), pady=8)

            self.gyear_vars = []
            self.gyear_buttons = []
            for i in range(1, 9):
                var = tk.IntVar(value=0)
                btn = tk.Checkbutton(
                    gradeyear_frame,
                    text=str(i),
                    variable=var,
                    indicatoron=False,   # makes the checkbutton look like a toggle button
                    width=3,
                    padx=2,
                    pady=2,
                    state="disabled"
                )
                btn.grid(row=0, column=i-1, padx=2)
                self.gyear_vars.append(var)
                self.gyear_buttons.append(btn)
            
            tk.Label(inner, text="Reward (NT$/hr):", anchor="e").grid(row=6, column=0, sticky="e", padx=(0,12), pady=8)
            self.reward_label = tk.Label(inner, text="", anchor="w")
            self.reward_label.grid(row=6, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Location:", anchor="e").grid(row=7, column=0, sticky="e", padx=(0,12), pady=8)
            self.location_label = tk.Label(inner, text="", anchor="w")
            self.location_label.grid(row=7, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Time:", anchor="e").grid(row=8, column=0, sticky="e", padx=(0,12), pady=8)
            
            # Time selection with popup button
            time_frame = tk.Frame(inner)
            time_frame.grid(row=8, column=1, sticky="w", padx=(0,12), pady=8)
            
            self.time_slots = [False for _ in range(24*7)]  # list to hold time slot selections
            self.time_display = tk.Label(time_frame, text="No times selected", anchor="w", width=30, relief="sunken", bd=1)
            self.time_display.pack(side="left", padx=(0, 8))
            
            time_select_btn = tk.Button(time_frame, text="View Times", command=self.open_new_time_selector)
            time_select_btn.pack(side="left")

            tk.Label(inner, text="Description:", anchor="ne").grid(row=9, column=0, sticky="ne", padx=(0,12), pady=8)
            self.description_entry = tk.Text(
                inner,
                height=10,
                width=50,
                wrap="word",
                relief="sunken",
                bd=1,
                state="disabled",
                bg="lightgray"
            )
            self.description_entry.grid(row=9, column=1, sticky="ew", padx=(0,12), pady=8)

            self.log_label = tk.Label(inner, font=("Helvetica", 12), fg="red", text="")
            self.log_label.grid(row=10, column=0, columnspan=2, sticky="nsew")
            btn_frame = tk.Frame(inner)
            btn_frame.grid(row=11, column=0, columnspan=2, pady=18, sticky="n")
            btn_frame.grid_columnconfigure(0, weight=1)
            btn_frame.grid_columnconfigure(1, weight=1)

            cancel_btn = tk.Button(btn_frame, text="Cancel",
                command=self.cancel)
            post_btn = tk.Button(btn_frame, text="Delete Request",
                command=self.delete_request)
            # place the buttons in the frame so they are used and visible
            cancel_btn.grid(row=0, column=0, sticky="ew", padx=8)
            post_btn.grid(row=0, column=1, sticky="ew", padx=8)
        
        def open_new_time_selector(self):
            """Open popup dialog for time selection"""
            if self.delete_confirmation_issued:
                self.delete_confirmation_issued = False
                self.clear_log()
                return
            dialog = TimeSelectionDialog(self, self.time_slots, disabled=True, available=self.time_slots)
            self.wait_window(dialog)
            # Update display after dialog closes
            # Only for showing selected times, not editing, so no need to update self.time_slots
            # self.update_time_display()
        
        '''
        def update_time_display(self):
            """Update the time display label based on selected slots"""
            selected_count = sum(self.time_slots)
            if selected_count == 0:
                self.time_display.config(text="No times selected")
            else:
                self.time_display.config(text=f"{selected_count} time slot(s) selected")
        '''

        def update_time_display(self):
            """Update the time display label based on selected slots"""
            selected_count = sum(self.time_slots)
            if selected_count == 0:
                self.time_display.config(text="No times selected")
            else:
                self.time_display.config(text=f"{selected_count} time slot(s) selected")
       
        def delete_request(self):
            if not self.delete_confirmation_issued:
                self.log_message("Press Delete Request again to confirm deletion.")
                self.delete_confirmation_issued = True
                return
            
            success, msg = BackendAPI.admin_delete_request(self.session.u_id, self.r_id)
            if success:
                self.log_message("Request deleted successfully.")
                self.controller.show_frame("AdminSearchRequestPage")
            else:
                self.log_message(f"Failed to delete request: {msg}")

        def cancel(self):
            if self.delete_confirmation_issued:
                self.delete_confirmation_issued = False
                self.clear_log()
                return
            self.controller.frames["AdminSearchRequestPage"].switched_to(clear=False)
            self.controller.show_frame("AdminSearchRequestPage")
        
        def log_message(self, message):
            self.log_label.config(text=message)

        def clear_log(self):
            self.log_label.config(text="")

        def switched_to(self, item):
            self.delete_confirmation_issued = False
            if item is None:
                print("No item to enter.")
                return
            # populate fields from item
            r_id = item.get("r_id", "")
            u_id = item.get("u_id", "")
            role = item.get("role", "")
            subject = item.get("subject", "")
            target_gradeyear = item.get("target_gradeyear", "00000000")
            description = item.get("request_detail", "")
            reward = item.get("reward", 0)
            location = item.get("place", "")
            time_slots_str = item.get("time", "0" * 168)
            for i in range(24*7):
                self.time_slots[i] = (time_slots_str[i] == '1')
            self.update_time_display()
            self.clear_log()
            self.r_id = r_id
            self.u_id = u_id
            self.u_id_label.config(text=u_id)
            self.r_id_label.config(text=r_id)
            for i in range(8):
                if target_gradeyear[i] == '1':
                    self.gyear_vars[i].set(1)
                else:
                    self.gyear_vars[i].set(0)
            self.role_label.config(text=role)
            self.subject_label.config(text=subject)
            self.reward_label.config(text=str(reward))
            self.location_label.config(text=location)
            self.description_entry.config(state="normal")
            self.description_entry.delete("1.0", tk.END)
            self.description_entry.insert("1.0", description)
            self.description_entry.config(state="disabled")
        
    class AdminSearchTakePage(tk.Frame):
        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.controller = controller
            self.session = session
        # allow this page to expand to fill the 800x600 container
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)

            inner = tk.Frame(self, bd=8)
            inner.grid(row=0, column=0, sticky="nsew", padx=40, pady=20)

            # Add more widgets for posting requests here
            inner.grid_columnconfigure(0, weight=0)   # labels
            inner.grid_columnconfigure(1, weight=1)   # entry widgets expand
            inner.grid_rowconfigure(0, weight=0)
            inner.grid_rowconfigure(1, weight=0)
            inner.grid_rowconfigure(2, weight=0)
            inner.grid_rowconfigure(3, weight=0)
            inner.grid_rowconfigure(4, weight=0)


            label = tk.Label(inner, text="Admin Search Takes Page", font=("Helvetica", 20))
            label.grid(row=0, column=0, columnspan=2, pady=(0, 16))

            tk.Label(inner, text="Request Id:", anchor="e").grid(row=1, column=0, sticky="e", padx=(0,12), pady=8)
            self.r_id_entry = tk.Entry(inner, text="")
            self.r_id_entry.grid(row=1, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="User Id:", anchor="e").grid(row=2, column=0, sticky="e", padx=(0,12), pady=8)
            self.u_id_entry = tk.Entry(inner, text="")
            self.u_id_entry.grid(row=2, column=1, sticky="w", padx=(0,12), pady=8)

            self.log_label = tk.Label(inner, font=("Helvetica", 12), fg="red", text="")
            self.log_label.grid(row=3, column=0, columnspan=2, sticky="nsew")

            btn_frame = tk.Frame(inner)
            btn_frame.grid(row=4, column=0, columnspan=2, pady=18, sticky="n")
            btn_frame.grid_columnconfigure(0, weight=1)
            btn_frame.grid_columnconfigure(1, weight=1)

            back_btn = tk.Button(btn_frame, text="Back",
                 command=self.back)
            search_btn = tk.Button(btn_frame, text="Search",
                command=self.search_takes)
            
            # place the buttons in the frame so they are used and visible
            back_btn.grid(row=0, column=0, sticky="ew", padx=8)
            search_btn.grid(row=0, column=1, sticky="ew", padx=8)

        def search_takes(self):
            u_id = self.u_id_entry.get().strip()
            r_id = self.r_id_entry.get().strip()

            if not u_id.isdigit() and u_id != "":
                self.log_message("Invalid User Id.")
                return
            
            if not r_id.isdigit() and r_id != "":
                self.log_message("Invalid Request Id.")
                return

            if not u_id and not r_id:
                self.log_message("Please enter at least one search criterion.")
                return
            
            success, msg, results = BackendAPI.admin_search_takes(
                self.session.u_id, u_id=u_id, r_id=r_id)

            if not success:
                self.log_message(f"Search failed: {msg}")
                return
            
            if not results:
                self.log_message("No matching requests found.")
                return

            self.controller.frames["AdminSearchTakeResultPage"].switched_to(results)
            self.controller.show_frame("AdminSearchTakeResultPage")
            
        def back(self):
            self.controller.frames["AdminPage"].switched_to()
            self.controller.show_frame("AdminPage")
        
        def log_message(self, message):
            self.log_label.config(text=message)
        def clear_log(self):
            self.log_label.config(text="")
        def switched_to(self, clear=True):
            if clear:
                self.u_id_entry.delete(0, tk.END)
                self.r_id_entry.delete(0, tk.END)
            self.clear_log()

    class AdminSearchTakeResultPage(tk.Frame):
        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.controller = controller
            self.session = session

            label = tk.Label(self, text="Admin Search Takes Result Page", font=("Helvetica", 20))
            label.pack(pady=10, padx=10)

            # scrollable listbox you can append items to
            list_frame = tk.Frame(self)
            list_frame.pack(fill="both", expand=True, padx=10, pady=10)

            scrollbar = tk.Scrollbar(list_frame, orient="vertical")
            scrollbar.pack(side="right", fill="y")

            # use single selection so clicks map cleanly to one item
            self.result_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, selectmode="browse")
            self.result_listbox.pack(side="left", fill="both", expand=True)

            scrollbar.config(command=self.result_listbox.yview)

            # bind double-click and Enter to activate item
            self.result_listbox.bind("<Double-Button-1>", lambda e: self._on_item_activate())
            self.result_listbox.bind("<Return>", lambda e: self._on_item_activate())

            # log label
            self.log_label = tk.Label(self, font=("Helvetica", 12), fg="red", text="")
            self.log_label.pack(pady=5)

            # back button
            back_button = tk.Button(self, text="Back",
                                command=self.go_back)
            back_button.pack(pady=10)

        def append_item(self, item=None):
            """
            Append an item to the listbox. Optionally provide a callback
            function that will be called when the item is activated.
            The callback receives (text, index).
            """
            if item is None:
                text = "No takes found."
            else:
                text = f"r_id = {item['r_id']} | u_id = {item['u_id']} | {item['time_ranges']}"
            self.result_listbox.insert(tk.END, text)
            # keep the newest item visible
            self.result_listbox.see(tk.END)

        def _on_item_activate(self):
            selection = self.result_listbox.curselection()
            if not selection:
                return
            idx = selection[0] # get the selected index
            item_text = self.result_listbox.get(idx)
            callback = self.enter_item(self.items[idx])
            if callback:
                callback(item_text, idx)

        def clear_items(self):
            self.result_listbox.delete(0, tk.END)
        
        def load_items(self, items):
            self.items = items
            self.clear_items()
            for item in items:
                self.append_item(item)

        def enter_item(self, item):
            if item is None:
                print("No item to enter.")
                return
            self.controller.frames["AdminTakeDetailPage"].switched_to(item)
            self.controller.show_frame("AdminTakeDetailPage")

        def go_back(self):
            self.controller.frames["AdminSearchTakePage"].switched_to(clear=False)
            self.controller.show_frame("AdminSearchTakePage")
            

        def switched_to(self, items=None):
            if not items:
                self.clear_items()
                self.append_item(None)
                self.items = []
                return
            self.load_items(items)
            self.items = items
        
        def log_message(self, message):
            self.log_label.config(text=message)
        
        def clear_log(self):
            self.log_label.config(text="")

    class AdminTakeDetailPage(tk.Frame):
        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.controller = controller
            self.session = session

            self.delete_confirmation_issued = False
            
            # allow this page to expand to fill the 800x600 container
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)

            inner = tk.Frame(self, bd=8)
            inner.grid(row=0, column=0, sticky="nsew", padx=40, pady=20)
            
            # Add more widgets for posting requests here
            inner.grid_columnconfigure(0, weight=0)   # labels
            inner.grid_columnconfigure(1, weight=1)   # entry widgets expand
            inner.grid_rowconfigure(0, weight=0)  # title
            inner.grid_rowconfigure(1, weight=0)  # r_id
            inner.grid_rowconfigure(2, weight=0)  # Taker u_id
            inner.grid_rowconfigure(3, weight=0)  # time
            inner.grid_rowconfigure(4, weight=0)  # log label
            inner.grid_rowconfigure(5, weight=0)  # buttons

            label = tk.Label(inner, text="Admin Take Detail Page", font=("Helvetica", 20))
            label.grid(row=0, column=0, columnspan=2, pady=(0, 16))

            tk.Label(inner, text="Request ID:", anchor="e").grid(row=1, column=0, sticky="e", padx=(0,12), pady=8)
            self.r_id_label = tk.Label(inner, text="", anchor="w")
            self.r_id_label.grid(row=1, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Taker User ID:", anchor="e").grid(row=2, column=0, sticky="e", padx=(0,12), pady=8)
            self.u_id_label = tk.Label(inner, text="", anchor="w")
            self.u_id_label.grid(row=2, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Time:", anchor="e").grid(row=3, column=0, sticky="e", padx=(0,12), pady=8)
            
            # Time selection with popup button
            time_frame = tk.Frame(inner)
            time_frame.grid(row=3, column=1, sticky="w", padx=(0,12), pady=8)
            
            self.time_slots = [False for _ in range(24*7)]  # list to hold time slot selections
            self.time_display = tk.Label(time_frame, text="No times selected", anchor="w", width=30, relief="sunken", bd=1)
            self.time_display.pack(side="left", padx=(0, 8))
            
            time_select_btn = tk.Button(time_frame, text="View Times", command=self.open_new_time_selector)
            time_select_btn.pack(side="left")

            self.log_label = tk.Label(inner, font=("Helvetica", 12), fg="red", text="")
            self.log_label.grid(row=4, column=0, columnspan=2, sticky="nsew")
            btn_frame = tk.Frame(inner)
            btn_frame.grid(row=5, column=0, columnspan=2, pady=18, sticky="n")
            btn_frame.grid_columnconfigure(0, weight=1)
            btn_frame.grid_columnconfigure(1, weight=1)

            cancel_btn = tk.Button(btn_frame, text="Cancel",
                command=self.cancel)
            post_btn = tk.Button(btn_frame, text="Delete Take",
                command=self.delete_take)
            # place the buttons in the frame so they are used and visible
            cancel_btn.grid(row=0, column=0, sticky="ew", padx=8)
            post_btn.grid(row=0, column=1, sticky="ew", padx=8)
        
        def open_new_time_selector(self):
            """Open popup dialog for time selection"""
            if self.delete_confirmation_issued:
                self.delete_confirmation_issued = False
                self.clear_log()
                return
            dialog = TimeSelectionDialog(self, self.time_slots, disabled=True, available=self.time_slots)
            self.wait_window(dialog)
            # Update display after dialog closes
            # Only for showing selected times, not editing, so no need to update self.time_slots
            # self.update_time_display()
        
        '''
        def update_time_display(self):
            """Update the time display label based on selected slots"""
            selected_count = sum(self.time_slots)
            if selected_count == 0:
                self.time_display.config(text="No times selected")
            else:
                self.time_display.config(text=f"{selected_count} time slot(s) selected")
        '''

        def update_time_display(self, txt=None):
            """Update the time display label based on selected slots"""
            selected_count = sum(self.time_slots)
            if selected_count == 0:
                self.time_display.config(text=txt or "No times selected")
            else:
                self.time_display.config(text=txt or f"{selected_count} time slot(s) selected")
       
        def delete_take(self):
            if not self.delete_confirmation_issued:
                self.log_message("Press Delete Take again to confirm deletion.")
                self.delete_confirmation_issued = True
                return
            
            success, msg = BackendAPI.admin_delete_take(self.session.u_id, self.r_id, self.u_id)
            if not success:
                self.log_message(f"Failed to delete take: {msg}")
                return
            
            self.log_message("Take deleted successfully.")
            self.controller.show_frame("AdminSearchTakePage")

        def cancel(self):
            if self.delete_confirmation_issued:
                self.delete_confirmation_issued = False
                self.clear_log()
                return
            
            self.controller.show_frame("AdminSearchTakeResultPage")

        def log_message(self, message):
            self.log_label.config(text=message)

        def clear_log(self):
            self.log_label.config(text="")

        def switched_to(self, item):
            self.delete_confirmation_issued = False
            if item is None:
                print("No item to enter.")
                return
            # populate fields from item
            r_id = item.get("r_id", "")
            u_id = item.get("u_id", "")
            
            time_slots_str = item.get("time", "0" * 168)
            time_txt = item.get("time_ranges", "")
            for i in range(24*7):
                self.time_slots[i] = (time_slots_str[i] == '1')
            self.update_time_display(txt=time_txt)
            self.clear_log()
            self.r_id = r_id
            self.u_id = u_id
            self.u_id_label.config(text=u_id)
            self.r_id_label.config(text=r_id)
    
    class AdminSearchCoursePage(tk.Frame):
        
        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.controller = controller
            self.session = session
        # allow this page to expand to fill the 800x600 container
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)

            inner = tk.Frame(self, bd=8)
            inner.grid(row=0, column=0, sticky="nsew", padx=40, pady=20)

            # Add more widgets for posting requests here
            inner.grid_columnconfigure(0, weight=0)   # labels
            inner.grid_columnconfigure(1, weight=1)   # entry widgets expand
            inner.grid_rowconfigure(0, weight=0)
            inner.grid_rowconfigure(1, weight=0)
            inner.grid_rowconfigure(2, weight=0)
            inner.grid_rowconfigure(3, weight=0)


            label = tk.Label(inner, text="Admin Search Course Page", font=("Helvetica", 20))
            label.grid(row=0, column=0, columnspan=2, pady=(0, 16))

            tk.Label(inner, text="Course Id:", anchor="e").grid(row=1, column=0, sticky="e", padx=(0,12), pady=8)
            self.c_id_entry = tk.Entry(inner, text="")
            self.c_id_entry.grid(row=1, column=1, sticky="w", padx=(0,12), pady=8)

            self.log_label = tk.Label(inner, font=("Helvetica", 12), fg="red", text="")
            self.log_label.grid(row=2, column=0, columnspan=2, sticky="nsew")

            btn_frame = tk.Frame(inner)
            btn_frame.grid(row=3, column=0, columnspan=2, pady=18, sticky="n")
            btn_frame.grid_columnconfigure(0, weight=1)
            btn_frame.grid_columnconfigure(1, weight=1)

            back_btn = tk.Button(btn_frame, text="Back",
                 command=self.back)
            search_btn = tk.Button(btn_frame, text="Search",
                command=self.search_course)
            
            # place the buttons in the frame so they are used and visible
            back_btn.grid(row=0, column=0, sticky="ew", padx=8)
            search_btn.grid(row=0, column=1, sticky="ew", padx=8)

        def search_course(self):
            c_id = self.c_id_entry.get().strip()

            if not c_id.isdigit() and c_id != "":
                self.log_message("Invalid Course Id.")
                return
            
            if not c_id:
                self.log_message("Please enter Course Id.")
                return
            
            success, msg, result = BackendAPI.admin_search_course(
                self.session.u_id, c_id=c_id)

            if not success:
                self.log_message(f"Search failed: {msg}")
                return
            
            if not result:
                self.log_message("No matching requests found.")
                return

            self.controller.frames["AdminEditCoursePage"].switched_to(result)
            self.controller.show_frame("AdminEditCoursePage")
            
        def back(self):
            self.controller.frames["AdminPage"].switched_to()
            self.controller.show_frame("AdminPage")
        
        def log_message(self, message):
            self.log_label.config(text=message)
        def clear_log(self):
            self.log_label.config(text="")
        def switched_to(self, clear=True):
            if clear:
                self.c_id_entry.delete(0, tk.END)
            self.clear_log()

    class AdminEditCoursePage(tk.Frame):
        def __init__(self, parent, controller, session: Session):
            super().__init__(parent)
            self.controller = controller
            self.session = session

            self.item = None

            self.delete_confirmation_issued = False
            self.reset_confirmation_issued = False            
            # allow this page to expand to fill the 800x600 container
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)

            inner = tk.Frame(self, bd=8)
            inner.grid(row=0, column=0, sticky="nsew", padx=40, pady=20)
            
            # Add more widgets for posting requests here
            inner.grid_columnconfigure(0, weight=0)   # labels
            inner.grid_columnconfigure(1, weight=1)   # entry widgets expand
            inner.grid_rowconfigure(0, weight=0)
            inner.grid_rowconfigure(1, weight=0)
            inner.grid_rowconfigure(2, weight=0)
            inner.grid_rowconfigure(3, weight=0)
            inner.grid_rowconfigure(4, weight=0)
            inner.grid_rowconfigure(5, weight=0)
            inner.grid_rowconfigure(6, weight=0)
            inner.grid_rowconfigure(7, weight=0)
            inner.grid_rowconfigure(8, weight=0) 
            inner.grid_rowconfigure(9, weight=0) # description expands
            
            
            label = tk.Label(inner, text="Admin Edit Course Page", font=("Helvetica", 20))
            label.grid(row=0, column=0, columnspan=2, pady=(0, 16))

            tk.Label(inner, text="Course ID:", anchor="e").grid(row=1, column=0, sticky="e", padx=(0,12), pady=8)
            self.c_id_label = tk.Label(inner, text="", anchor="w")
            self.c_id_label.grid(row=1, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Request ID:", anchor="e").grid(row=2, column=0, sticky="e", padx=(0,12), pady=8)
            self.r_id_label = tk.Label(inner, text="", anchor="w")
            self.r_id_label.grid(row=2, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Student User ID:", anchor="e").grid(row=3, column=0, sticky="e", padx=(0,12), pady=8)
            self.student_u_id_label = tk.Label(inner, text="", anchor="w")
            self.student_u_id_label.grid(row=3, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Student Score:", anchor="e").grid(row=4, column=0, sticky="e", padx=(0,12), pady=8)
            self.student_score_label = tk.Label(inner, text="", anchor="w")
            self.student_score_label.grid(row=4, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Teacher User ID:", anchor="e").grid(row=5, column=0, sticky="e", padx=(0,12), pady=8)
            self.teacher_u_id_label = tk.Label(inner, text="", anchor="w")
            self.teacher_u_id_label.grid(row=5, column=1, sticky="w", padx=(0,12), pady=8)
            
            tk.Label(inner, text="Teacher Score:", anchor="e").grid(row=6, column=0, sticky="e", padx=(0,12), pady=8)
            self.teacher_score_label = tk.Label(inner, text="", anchor="w")
            self.teacher_score_label.grid(row=6, column=1, sticky="w", padx=(0,12), pady=8)

            tk.Label(inner, text="Status:", anchor="e").grid(row=7, column=0, sticky="e", padx=(0,12), pady=8)
            self.status_label = tk.Label(inner, text="", anchor="w")
            self.status_label.grid(row=7, column=1, sticky="w", padx=(0,12), pady=8)

            self.log_label = tk.Label(inner, font=("Helvetica", 12), fg="red", text="")
            self.log_label.grid(row=8, column=0, columnspan=2, sticky="nsew")
            btn_frame = tk.Frame(inner)
            btn_frame.grid(row=9, column=0, columnspan=2, pady=18, sticky="n")
            btn_frame.grid_columnconfigure(0, weight=1)
            btn_frame.grid_columnconfigure(1, weight=1)
            btn_frame.grid_columnconfigure(2, weight=1)

            cancel_btn = tk.Button(btn_frame, text="Cancel",
                command=self.cancel)
            reset_score_button = tk.Button(btn_frame, text="Reset Scores",
                command=self.reset_score)
            delete_btn = tk.Button(btn_frame, text="Delete Course",
                command=self.delete_course)
            # place the buttons in the frame so they are used and visible
            cancel_btn.grid(row=0, column=0, sticky="ew", padx=8)
            reset_score_button.grid(row=0, column=1, sticky="ew", padx=8)
        
               
        def reset_score(self):
            if self.delete_confirmation_issued:
                self.delete_confirmation_issued = False
                self.clear_log()
                return
            
            if self.item is None:
                print("No item to reset.")
                return
            
            if self.item.get("student_score", None) is None and self.item.get("teacher_score", None) is None:
                self.log_message("Scores are already None.")
                return

            if not self.reset_confirmation_issued:
                self.log_message("Press Reset Scores again to confirm reset.")
                self.reset_confirmation_issued = True
                return
            
            success, msg = BackendAPI.admin_reset_course_rating(self.session.u_id, self.c_id)
            if not success:
                self.log_message(f"Failed to reset scores: {msg}")
                return

            # reset both scores
            self.student_score_label.config(text="None")
            self.teacher_score_label.config(text="None")
            self.item["student_score"] = None
            self.item["teacher_score"] = None

        def cancel(self):
            if self.reset_confirmation_issued or self.delete_confirmation_issued:
                self.reset_confirmation_issued = False
                self.delete_confirmation_issued = False
                self.clear_log()
                return
            self.controller.show_frame("AdminSearchCoursePage")
        
        def delete_course(self):
            if self.reset_confirmation_issued:
                self.reset_confirmation_issued = False
                self.clear_log()
                return
            if self.item is None:
                print("No item to delete.")
                return
            if self.item.get("status", "") != "ongoing":
                self.log_message("Only ongoing courses can be deleted.")
                return
            if not self.delete_confirmation_issued:
                self.log_message("Press Delete Course again to confirm deletion.")
                self.delete_confirmation_issued = True
                return
            success, msg = BackendAPI.admin_delete_course(self.session.u_id, self.c_id)
            if success:
                self.log_message("Course deleted successfully.")
                self.controller.frames["AdminSearchCoursePage"].switched_to(clear=True)
                self.controller.show_frame("AdminSearchCoursePage")
            else:
                self.log_message(f"Failed to delete course: {msg}")

        def log_message(self, message):
            self.log_label.config(text=message)

        def clear_log(self):
            self.log_label.config(text="")

        def switched_to(self, item):
            self.delete_confirmation_issued = False
            self.reset_confirmation_issued = False
            self.item = item
            if item is None:
                print("No item to enter.")
                return
            
            # populate fields from item
            c_id = item.get("c_id", "")
            r_id = item.get("r_id", "")
            student_u_id = item.get("student_u_id", "")
            student_score = item.get("student_score", None)
            teacher_u_id = item.get("teacher_u_id", "")
            teacher_score = item.get("teacher_score", None)
            status = item.get("status", "ongoing")
            self.c_id = c_id
            self.r_id = r_id
            self.c_id_label.config(text=c_id)
            self.r_id_label.config(text=r_id)
            self.student_u_id_label.config(text=student_u_id)
            self.student_score_label.config(text=str(student_score) if student_score is not None else "None")
            self.teacher_u_id_label.config(text=teacher_u_id)
            self.teacher_score_label.config(text=str(teacher_score) if teacher_score is not None else "None")
            self.status_label.config(text=status)

    class AppController:
        def __init__(self, container):

            self.session = Session()
            self.container = container
            self.frames = {}
            
            pages = {
                "LoginPage": LoginPage,
                "UserPage": UserPage,
                "SignUpPage": SignUpPage,
                "EditPasswordPage": EditPasswordPage,
                "PostRequestPage": PostRequestPage,
                "MyRequestResultPage": MyRequestResultPage,
                "EditRequestPage": EditRequestPage,
                "SearchRequestPage": SearchRequestPage,
                "SearchRequestResultPage": SearchRequestResultPage,
                "ViewTakeResultPage": ViewTakeResultPage,
                "TakeDetailPage": TakeDetailPage,
                "MyCoursesPage": MyCoursesPage,
                "CourseDetailPage": CourseDetailPage,
                "ViewRequestDetailPage": ViewRequestDetailPage,
                "AdminPage": AdminPage,
                "AdminSearchUserPage": AdminSearchUserPage,
                "AdminUserDetailPage": AdminUserDetailPage,
                "AdminSearchRequestPage": AdminSearchRequestPage,
                "AdminSearchRequestResultPage": AdminSearchRequestResultPage,
                "AdminEditRequestPage": AdminEditRequestPage,
                "AdminSearchTakePage": AdminSearchTakePage,
                "AdminSearchTakeResultPage": AdminSearchTakeResultPage,
                "AdminTakeDetailPage": AdminTakeDetailPage,
                "AdminSearchCoursePage": AdminSearchCoursePage,
                "AdminEditCoursePage": AdminEditCoursePage

            }

            for name, F in pages.items():
                frame = F(container, self, self.session)
                self.frames[name] = frame
                frame.grid(row=0, column=0, sticky="nsew")

            container.grid_rowconfigure(0, weight=1)
            container.grid_columnconfigure(0, weight=1)
            self.frames["LoginPage"].switched_to()
            self.show_frame("LoginPage")

        def show_frame(self, name):
            frame = self.frames[name]
            frame.tkraise()

    app = AppController(container)
    app.show_frame("LoginPage")

    root.mainloop()


if __name__ == "__main__":
    main()