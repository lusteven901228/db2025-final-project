"""
Backend API Layer for Interface
This module provides a clean interface between the GUI (interface.py) and database operations (back_DB.py)
All functions return structured data that can be easily consumed by the GUI

Session Management:
- Use Session class to store user credentials after login
- Pass session object to methods that need authentication
- No need to pass password everywhere
"""

from back_DB import (
    # API functions with arguments (no input() calls)
    api_sign_up,
    api_login,
    api_edit_password,
    api_delete_account,
    api_post_request,
    api_my_request,
    api_delete_request,
    api_search_request,
    api_take_request,
    api_my_take_request,
    api_delete_take_request,
    api_my_taken_by,
    api_my_request_taken_by,
    api_confirm_request_taken_by,
    api_deny_request_taken_by,
    api_my_course,
    api_rate_course,
    # Admin API functions
    api_admin_search_user,
    api_admin_edit_user_password,
    api_admin_edit_user_role,
    api_admin_suspend_user,
    api_admin_search_request,
    api_admin_delete_request,
    api_admin_search_take_request,
    api_admin_delete_take_request,
    api_admin_search_course,
    api_admin_delete_course,
    api_admin_reset_course_rate,
    # Utility functions
    convert_168bit_to_ranges,
    convert_grade_bits
)


# ==================== Session Management ====================

class Session:
    """
    User session to store authentication state
    Use this instead of passing passwords around
    """
    def __init__(self):
        self.is_authenticated = False
        self.u_id = None
        self.username = None
        self.password = None  # Stored securely in session
        self.realname = None
        self.email = None
        self.role = None
        self.status = None
    
    def login(self, user_data, password):
        """Store user info after successful login"""
        self.is_authenticated = True
        self.u_id = user_data['u_id']
        self.username = user_data['username']
        self.password = password  # Keep for operations requiring verification
        self.realname = user_data['realname']
        self.email = user_data['email']
        self.role = user_data['role']
        self.status = user_data['status']
    
    def logout(self):
        """Clear session data"""
        self.is_authenticated = False
        self.u_id = None
        self.username = None
        self.password = None
        self.realname = None
        self.email = None
        self.role = None
        self.status = None
    
    def get_user_info(self):
        """Get current user info as dict"""
        if not self.is_authenticated:
            return None
        return {
            'u_id': self.u_id,
            'username': self.username,
            'realname': self.realname,
            'email': self.email,
            'role': self.role,
            'status': self.status
        }
    
    def require_auth(self):
        """Check if user is authenticated, return (bool, message)"""
        if not self.is_authenticated:
            return (False, "請先登入")
        if self.status != "active":
            return (False, f"帳號狀態為 {self.status}，無法執行操作")
        return (True, "")


# Global session instance (for simple usage)
# In a real app, you might use Flask sessions or similar
current_session = Session()

class BackendAPI:
    """
    Clean API wrapper for GUI integration
    All methods return (success: bool, message: str, data: any) tuples
    
    Usage with Session:
        session = Session()
        success, msg, data = BackendAPI.login_with_session(session, "username", "password")
        if success:
            # Now session is authenticated
            BackendAPI.my_requests_session(session)
    """
    
    # ==================== Authentication ====================
    
    @staticmethod
    def signup(username, password, confirm_password, realname, email):
        """
        Register a new user
        Returns: (bool, str, dict) - (success, message, user_data)
        """
        return api_sign_up(username, password, confirm_password, realname, email)
    
    @staticmethod
    def login(username, password):
        """
        Authenticate user
        Returns: (bool, str, dict) - (success, message, user_info)
        user_info contains: u_id, username, role, status, realname, email
        """
        return api_login(username, password)
       
    # ==================== Password Management ====================
    
    @staticmethod
    def edit_password(username, realname, old_password, new_password):
        """
        Change user password
        Returns: (bool, str) - (success, message)
        """
        return api_edit_password(username, realname, old_password, new_password)
    
    
    @staticmethod
    def delete_account(username, password, realname):
        """
        Soft delete user account
        Returns: (bool, str) - (success, message)
        """
        return api_delete_account(username, password, realname)

    
    # ==================== Request Management ====================
    
    @staticmethod
    def post_request(u_id, role, target_gradeyear, subject, request_detail, reward, place, time_bits=None):
        """
        Create a new course request
        Args:
            u_id: user id
            role: "teacher" or "student"
            target_gradeyear: 8-bit string (e.g., "10000000" for grade 1)
            subject: subject name
            request_detail: description
            reward: hourly rate (int or str)
            place: location
            time_bits: 168-bit string (optional, defaults to "1" + "0"*167)
        Returns: (bool, str, int) - (success, message, r_id)
        """
        return api_post_request(u_id, role, target_gradeyear, subject, request_detail, reward, place, time_bits)
    
    @staticmethod
    def get_my_requests(u_id):
        """
        Get all active requests posted by user
        Returns: (bool, str, list) - (success, message, [request_dict, ...])
        """
        return api_my_request(u_id)
   
    @staticmethod
    def delete_request(u_id, r_id):
        """
        Delete (soft) a request
        Returns: (bool, str) - (success, message)
        """
        return api_delete_request(u_id, r_id)
    
    @staticmethod
    def search_request(role=None, username=None, subject=None, target_bits=None, time_bits=None,
                       request_detail=None, min_reward=None, max_reward=None, place=None):
        """
        Search for requests with filters
        All parameters are optional
        Returns: (bool, str, list) - (success, message, [request_dict, ...])
        """
        return api_search_request(role, username, subject, target_bits, time_bits, request_detail, min_reward, max_reward, place)
    
    # ==================== Take Request (Apply) ====================
    
    @staticmethod
    def take_request(u_id, r_id, time):
        """
        Apply to a request
        Returns: (bool, str) - (success, message)
        """
        return api_take_request(u_id, r_id, time)
    
    @staticmethod
    def my_takes(u_id):
        """
        Get all requests I've applied to
        Returns: (bool, str, list) - (success, message, [take_dict, ...])
        """
        return api_my_take_request(u_id)
    
    @staticmethod
    def delete_take(u_id, r_id):
        """
        Cancel an application
        Returns: (bool, str) - (success, message)
        """
        return api_delete_take_request(u_id, r_id)
    
    # ==================== Request Owner Actions ====================
    
    @staticmethod
    def my_taken_by(u_id):
        """
        View who has applied to my requests
        Returns: (bool, str, list) - (success, message, [applicant_dict, ...])
        """
        return api_my_taken_by(u_id)
    
    @staticmethod
    def my_request_taken_by(u_id, r_id):
        """
        View who has applied to a specific request of mine
        Returns: (bool, str, list) - (success, message, [applicant_dict, ...])
        """
        return api_my_request_taken_by(u_id, r_id)
    
    @staticmethod
    def confirm_applicant(taker_u_id, r_id, owner_u_id):
        """
        Accept an applicant and create a course
        Returns: (bool, str, int) - (success, message, c_id)
        """
        return api_confirm_request_taken_by(taker_u_id, r_id, owner_u_id)
    
    @staticmethod
    def deny_applicant(taker_u_id, r_id, owner_u_id):
        """
        Reject an applicant
        Returns: (bool, str) - (success, message)
        """
        return api_deny_request_taken_by(taker_u_id, r_id, owner_u_id)
    
    # ==================== Course Management ====================
    
    @staticmethod
    def my_courses(u_id):
        """
        Get all courses (as teacher and as student)
        Returns: (bool, str, dict) - (success, message, {"as_teacher": [...], "as_student": [...]})
        """
        return api_my_course(u_id)
    
    @staticmethod
    def rate_course(u_id, c_id, score):
        """
        Rate a course (teacher rates student or vice versa)
        Args:
            score: float between 1 and 5
        Returns: (bool, str) - (success, message)
        """
        return api_rate_course(u_id, c_id, score)
    
    # ==================== Utility Functions ====================
    
    @staticmethod
    def parse_time_bits(bit_string_168):
        """
        Convert 168-bit time string to readable format
        Returns: list of strings like ["Monday 9:00~17:00", ...]
        """
        return convert_168bit_to_ranges(bit_string_168)
    
    @staticmethod
    def parse_grade_bits(bit_string_8):
        """
        Convert 8-bit grade string to readable format
        Returns: string like "1, 2, 3" or "None"
        """
        return convert_grade_bits(bit_string_8)
    
    @staticmethod
    def create_time_bits(selected_slots):
        """
        Create 168-bit string from selected time slots
        Args:
            selected_slots: dict like {("Monday", 9): True, ("Monday", 10): True, ...}
        Returns: 168-bit string
        """
        days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        bits = ['0'] * 168
        
        for (day, hour), is_selected in selected_slots.items():
            if is_selected and day in days:
                day_index = days.index(day)
                bit_index = day_index * 24 + hour
                if 0 <= bit_index < 168:
                    bits[bit_index] = '1'
        
        return ''.join(bits)
    
    @staticmethod
    def create_grade_bits(grade_list):
        """
        Create 8-bit string from grade list
        Args:
            grade_list: list of ints like [1, 2, 3] representing grades
        Returns: 8-bit string
        """
        bits = ['0'] * 8
        for grade in grade_list:
            if 1 <= grade <= 8:
                bits[grade - 1] = '1'
        return ''.join(bits)
    
    # ==================== Admin Functions ====================


    @staticmethod
    def _require_admin(session):
        """Check if session is admin"""
        if session.role != "admin":
            return (False, "需要管理員權限")
        return (True, "")
    
    @staticmethod
    def admin_search_user(admin_u_id, u_id):
        """
        Admin: Search for user by u_id
        Returns: (bool, str, dict) - (success, message, user_data)
        """
        return api_admin_search_user(admin_u_id, u_id)
    
    @staticmethod
    def admin_edit_user_password(admin_u_id, target_u_id, new_password):
        """
        Admin: Change user's password
        Returns: (bool, str) - (success, message)
        """
        return api_admin_edit_user_password(admin_u_id, target_u_id, new_password)
    
    @staticmethod
    def admin_edit_user_role(admin_u_id, target_u_id, new_role):
        """
        Admin: Change user's role
        Returns: (bool, str) - (success, message)
        """
        return api_admin_edit_user_role(admin_u_id, target_u_id, new_role)
    
    @staticmethod
    def admin_suspend_user(admin_u_id, target_u_id):
        """
        Admin: Suspend a user account
        Returns: (bool, str) - (success, message)
        """
        return api_admin_suspend_user(admin_u_id, target_u_id)
    
    @staticmethod
    def admin_search_requests(admin_u_id, r_id=None, u_id=None):
        """
        Admin: Search requests by r_id and/or u_id
        At least one parameter must be provided
        Returns: (bool, str, list) - (success, message, [request_dict, ...])
        """
        return api_admin_search_request(admin_u_id, r_id, u_id)
    
    @staticmethod
    def admin_delete_request(admin_u_id, r_id):
        """
        Admin: Delete a request
        Returns: (bool, str) - (success, message)
        """
        return api_admin_delete_request(admin_u_id, r_id)
    
    @staticmethod
    def admin_search_takes(admin_u_id, r_id=None, u_id=None):
        """
        Admin: Search take_request by r_id and/or u_id
        At least one parameter must be provided
        Returns: (bool, str, list) - (success, message, [take_dict, ...])
        """
        return api_admin_search_take_request(admin_u_id, r_id, u_id)
    
    @staticmethod
    def admin_delete_take(admin_u_id, r_id, u_id):
        """
        Admin: Delete a take_request record
        Returns: (bool, str) - (success, message)
        """
        return api_admin_delete_take_request(admin_u_id, r_id, u_id)
    
    @staticmethod
    def admin_search_course(admin_u_id, c_id):
        """
        Admin: Search course by c_id
        Returns: (bool, str, dict) - (success, message, course_data)
        """
        return api_admin_search_course(admin_u_id, c_id)
    
    @staticmethod
    def admin_delete_course(admin_u_id, c_id):
        """
        Admin: Delete a course
        Returns: (bool, str) - (success, message)
        """
        return api_admin_delete_course(admin_u_id, c_id)
    
    @staticmethod
    def admin_reset_course_rating(admin_u_id, c_id):
        """
        Admin: Reset course ratings to NULL
        Returns: (bool, str) - (success, message)
        """
        return api_admin_reset_course_rate(admin_u_id, c_id)


# ==================== Simple Test Functions ====================

def test_backend():
    """Test basic backend functionality"""
    print("=" * 60)
    print("Backend API Test")
    print("=" * 60)
    
    # Test signup
    print("\n1. Testing Signup...")
    success, msg, data = BackendAPI.signup("testuser123", "pass123", "pass123", "Test User", "test@example.com")
    print(f"   Result: {success}, Message: {msg}")
    if data:
        print(f"   User ID: {data.get('u_id')}")
    
    # Test login
    print("\n2. Testing Login...")
    success, msg, data = BackendAPI.login("testuser123", "pass123")
    print(f"   Result: {success}, Message: {msg}")
    if data:
        print(f"   User Info: {data}")
    
    # Test search
    print("\n3. Testing Search Requests...")
    success, msg, results = BackendAPI.search_request(subject="Math")
    print(f"   Result: {success}, Message: {msg}")
    print(f"   Found {len(results)} requests")
    
    # Test utility
    print("\n4. Testing Utility Functions...")
    time_bits = "1" * 24 + "0" * 144  # All Monday
    print(f"   Time ranges: {BackendAPI.parse_time_bits(time_bits)}")
    
    grade_bits = "10100000"  # Grades 1 and 3
    print(f"   Grades: {BackendAPI.parse_grade_bits(grade_bits)}")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
   
    test_backend()
