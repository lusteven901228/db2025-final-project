import psycopg2
from tabulate import tabulate
import hashlib
import random
import string
import os

# ------------------ DB Layer ------------------
def get_connection():
    return psycopg2.connect(
        database="db2025_final4",
        # user="postgres"
    )

# password hash
def hash_password(password):
    """
    Hash a password using PBKDF2 with SHA256
    Returns: salt$hash (hex encoded)
    """
    salt = os.urandom(32)  # 32 bytes = 256 bits
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + '$' + pwdhash.hex()

def verify_password(stored, provided):
    """
    Verify a password against a stored hash
    stored format: salt$hash (hex encoded)
    Returns: True if password matches, False otherwise
    """
    if not stored or '$' not in stored:
        return False
    
    try:
        salt_hex, hash_hex = stored.split('$')
        salt = bytes.fromhex(salt_hex)
        stored_hash = bytes.fromhex(hash_hex)
        
        pwdhash = hashlib.pbkdf2_hmac('sha256', provided.encode('utf-8'), salt, 100000)
        return pwdhash == stored_hash
    except (ValueError, AttributeError):
        return False

#------------------168bit轉時間-------------------
def convert_168bit_to_ranges(bitstring):
    if len(bitstring) != 168:
        return ["Invalid length (must be 168 bits)"]

    days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    results = []

    for day_index in range(7):
        day_bits = bitstring[day_index*24:(day_index+1)*24]

        start = None
        for hour in range(24):
            if day_bits[hour] == "1":
                if start is None:
                    start = hour
            else:
                if start is not None:
                    results.append(f"{days[day_index]} {start}:00~{hour}:00")
                    start = None

        # 若一天最後仍在區段中，結束在 24:00
        if start is not None:
            results.append(f"{days[day_index]} {start}:00~24:00")

    return results
#------------------8bit轉年級-------------------
def convert_grade_bits(bit8):
    if len(bit8) != 8:
        return "Invalid (must be 8 bits)"

    grades = []
    grade_string = "一二三四五六七八"
    for i in range(8):
        if bit8[i] == "1":
            grades.append(grade_string[i])  # 第 0 bit → 1 年級

    if not grades:
        return ""

    return "、".join(grades) + "年級"

# ==================== REFACTORED API FUNCTIONS (for backend.py) ====================
# These functions accept arguments instead of using input(), return data structures
# All original functions below remain unchanged for CLI usage



def api_sign_up(username, password, confirm_password, realname, email):
    """
    註冊新使用者
    Returns: (success: bool, message: str, data: dict or None)
    """
    if not all([username, password, confirm_password, realname, email]):
        return (False, "所有欄位都必填！", None)

    if password != confirm_password:
        return (False, "密碼與確認密碼不一致！", None)
    
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 檢查 username
            cur.execute('SELECT COUNT(*) FROM "USER" WHERE username=%s', (username,))
            if cur.fetchone()[0] > 0:
                return (False, "username 已存在！", None)

            # 檢查 realname
            cur.execute('SELECT COUNT(*) FROM "USER" WHERE realname=%s', (realname,))
            if cur.fetchone()[0] > 0:
                return (False, "realname 已存在！", None)

            # 檢查 email
            cur.execute('SELECT COUNT(*) FROM "USER" WHERE email=%s', (email,))
            if cur.fetchone()[0] > 0:
                return (False, "email 已存在！", None)
            
            hashed_password = hash_password(password)

            # 執行signup
            cur.execute(
                'INSERT INTO "USER" (username, password, realname, email, role, status) VALUES (%s, %s, %s, %s, %s, %s) RETURNING u_id',
                (username, hashed_password, realname, email, 'user', 'active')
            )
            u_id = cur.fetchone()[0]
            conn.commit()
            return (True, "註冊成功！", {"u_id": u_id, "username": username, "realname": realname, "email": email, "role": "user"})
    except Exception as e:
        conn.rollback()
        return (False, f"錯誤：{str(e)}", None)
    finally:
        conn.close()

def api_login(username, password):
    """
    使用者登入
    Returns: (success: bool, message: str, data: dict or None)
    """
    if not username or not password:
        return (False, "帳號密碼不可為空", None)

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                '''
                SELECT u_id, password, role, status, realname, email
                FROM "USER" 
                WHERE username = %s
                ''',
                (username,)
            )
            result = cur.fetchone()

            if not result:
                return (False, "帳號或密碼錯誤！", None)

            stored_password = result[1]
            if not verify_password(stored_password, password):
                return (False, "帳號或密碼錯誤！", None)

            u_id, stored_password, role, status, realname, email = result

            if status != "active":
                return (False, f"登入失敗！你的帳號目前狀態為 {status}，無法登入。", None)

            return (True, f"登入成功！使用者角色：{role}", {
                "u_id": u_id,
                "username": username,
                "role": role,
                "status": status,
                "realname": realname,
                "email": email
            })

    except Exception as e:
        return (False, f"錯誤：{str(e)}", None)
    finally:
        conn.close()

def api_edit_password(username, realname, old_password, new_password):
    """
    修改密碼
    Returns: (success: bool, message: str)
    """
    if not all([username, realname, old_password, new_password]):
        return (False, "欄位不可為空！")

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 檢查 username + realname 是否一致
            cur.execute(
                'SELECT u_id, password FROM "USER" WHERE username=%s AND realname=%s',
                (username, realname)
            )
            result = cur.fetchone()
            if not result:
                return (False, "使用者不存在或資料不正確！")

            # 檢查舊密碼是否正確
            stored_password = result[1]
            if not verify_password(stored_password, old_password):
                return (False, "舊密碼不正確！")

            # 更新密碼
            hashed_new_password = hash_password(new_password)
            cur.execute(
                'UPDATE "USER" SET password=%s WHERE username=%s AND realname=%s',
                (hashed_new_password, username, realname)
            )
            conn.commit()
            return (True, "密碼修改成功！")

    except Exception as e:
        conn.rollback()
        return (False, f"錯誤：{str(e)}")
    finally:
        conn.close()

def api_delete_account(username, password, realname):
    """
    刪除帳號（標記刪除）
    Returns: (success: bool, message: str)
    """
    if not all([username, password, realname]):
        return (False, "所有欄位都必填！")

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 驗證使用者是否存在
            cur.execute(
                'SELECT u_id, password FROM "USER" WHERE username=%s AND realname=%s AND status != %s',
                (username, realname, "deleted")
            )
            result = cur.fetchone()

            if not result:
                return (False, "使用者不存在或資料不正確！")
            
            user_id = result[0]
            stored_password = result[1]
            if not verify_password(stored_password, password):
                return (False, "密碼不正確！")
            # 更新使用者狀態
            cur.execute(
                'UPDATE "USER" SET status=%s, delete_by=%s WHERE u_id=%s',
                ("deleted", user_id, user_id)
            )
            conn.commit()
            return (True, f"帳號已刪除")

    except Exception as e:
        conn.rollback()
        return (False, f"錯誤：{str(e)}")
    finally:
        conn.close()

def api_post_request(u_id, role, target_gradeyear, subject, request_detail, reward, place, time_bits=None):
    """
    發佈新課程請求
    Returns: (success: bool, message: str, r_id: int or None)
    """
    # 基本檢查
    if role not in ("teacher", "student"):
        return (False, "角色必須是 teacher 或 student", None)

    if len(target_gradeyear) != 8 or any(c not in "01" for c in target_gradeyear):
        return (False, "target_gradeyear 必須是 8-bit 0/1 字串", None)

    try:
        reward = int(reward)
    except ValueError:
        return (False, "reward 必須是整數", None)

    # 預設 time: 1 個 1 + 167 個 0
    if time_bits is None:
        time_bits = "1" + "0" * 167

    if len(time_bits) != 168 or any(c not in "01" for c in time_bits):
        return (False, "time 必須是 168-bit 0/1 字串", None)

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO user_request
                    (u_id, role, target_gradeyear, subject, request_detail, reward, place, time, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'active')
                RETURNING r_id
            """, (u_id, role, target_gradeyear, subject, request_detail, reward, place, time_bits))
            
            r_id = cur.fetchone()[0]
            conn.commit()
            return (True, f"課程請求已新增成功，r_id = {r_id}", r_id)

    except Exception as e:
        conn.rollback()
        return (False, f"錯誤：{str(e)}", None)
    finally:
        conn.close()

def api_my_request(u_id):
    """
    查看自己的 request
    Returns: (success: bool, message: str, data: list of dict)
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                '''
                SELECT r_id, u_id, time, role, subject, target_gradeyear,
                       request_detail, reward, place
                FROM user_request
                WHERE u_id=%s AND status=%s
                ''',
                (u_id, "active")
            )

            rows = cur.fetchall()

            if not rows:
                return (True, "查無 active request", [])

            results = []
            for r in rows:
                (r_id, u_id, bit168, role, subject, grade_bits,
                 request_detail, reward, place) = r

                results.append({
                    "r_id": r_id,
                    "u_id": u_id,
                    "time": bit168,
                    "time_ranges": convert_168bit_to_ranges(bit168),
                    "role": role,
                    "subject": subject,
                    "target_gradeyear": grade_bits,
                    "gradeyear_display": convert_grade_bits(grade_bits),
                    "request_detail": request_detail,
                    "reward": reward,
                    "place": place
                })

            return (True, f"找到 {len(results)} 筆 request", results)

    except Exception as e:
        return (False, f"錯誤：{str(e)}", [])
    finally:
        conn.close()

def api_delete_request(u_id, r_id):
    """
    刪除 Request
    Returns: (success: bool, message: str)
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 檢查 r_id 存不存在 + 是否屬於該 u_id
            cur.execute(
                '''
                SELECT u_id FROM user_request
                WHERE r_id = %s AND status != %s
                ''',
                (r_id, "deleted")
            )

            row = cur.fetchone()

            if not row:
                return (False, "找不到該 r_id")

            owner_u_id = row[0]

            if owner_u_id != u_id:
                return (False, "權限錯誤：該 request 不屬於此 u_id，無法刪除！")

            # 執行刪除（標記 deleted）
            cur.execute(
                '''
                UPDATE user_request
                SET status=%s, delete_by=%s
                WHERE r_id=%s
                ''',
                ("deleted", u_id, r_id)
            )

            conn.commit()
            return (True, f"Request {r_id} 已刪除")

    except Exception as e:
        conn.rollback()
        return (False, f"錯誤：{str(e)}")
    finally:
        conn.close()

def api_search_request(role=None, username=None, subject=None, target_bits=None, time_bits=None,
                        request_detail=None, min_reward=None, max_reward=None, place=None):
    """
    搜尋 Request (可部分搜尋)
    Returns: (success: bool, message: str, data: list of dict)
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 基本 SQL + JOIN USER
            sql = """
                SELECT 
                    r.r_id,
                    r.u_id,
                    u.username,
                    u.realname,
                    u.email,
                    r.time,
                    r.role,
                    r.subject,
                    r.target_gradeyear,
                    r.request_detail,
                    r.reward,
                    r.place
                FROM user_request r
                JOIN "USER" u ON r.u_id = u.u_id
                WHERE r.status='active'
            """

            params = []

            # 動態條件
            if username:
                sql += " AND u.username = %s"
                params.append(username)
            if role:
                sql += " AND r.role = %s"
                params.append(role)

            if subject:
                sql += " AND r.subject ILIKE %s"
                params.append(f"%{subject}%")

            if request_detail:
                sql += " AND r.request_detail ILIKE %s"
                params.append(f"%{request_detail}%")

            if place:
                sql += " AND r.place ILIKE %s"
                params.append(f"%{place}%")

            if min_reward:
                sql += " AND r.reward >= %s"
                params.append(min_reward)
                
            if max_reward:
                sql += " AND r.reward <= %s"
                params.append(max_reward)
            
            # time_bits（168bit AND 檢查是否有重疊）

            if False and time_bits:
                if len(time_bits) != 168 or any(c not in "01" for c in time_bits):
                    return (False, "time_bits 必須是 168 個 bit", [])

                sql += " AND (r.time & %s::bit(168)) <>"
                sql += " B'" + "0" * 168 + "'"
                params.append(time_bits)


            # target_gradeyear（8bit AND 檢查是否有重疊）
            if target_bits:
                if len(target_bits) != 8 or any(c not in "01" for c in target_bits):
                    return (False, "target_gradeyear 必須是 8 個 bit", [])

                sql += " AND (r.target_gradeyear & %s::BIT(8)) <> B'00000000'"
                params.append(target_bits)

            # 最後排序 + LIMIT
            sql += " ORDER BY r.reward ASC LIMIT 20"

            cur.execute(sql, tuple(params))
            rows = cur.fetchall()

            if not rows:
                return (True, "查無符合的 request", [])

            results = []
            for r in rows:
                (r_id, u_id, username, realname, email,
                 bit168, role, subject, grade_bits,
                 request_detail, reward, place) = r

                results.append({
                    "r_id": r_id,
                    "u_id": u_id,
                    "username": username,
                    "realname": realname,
                    "email": email,
                    "time": bit168,
                    "time_ranges": convert_168bit_to_ranges(bit168),
                    "role": role,
                    "subject": subject,
                    "target_gradeyear": grade_bits,
                    "gradeyear_display": convert_grade_bits(grade_bits),
                    "request_detail": request_detail,
                    "reward": reward,
                    "place": place
                })

            return (True, f"找到 {len(results)} 筆 request", results)

    except Exception as e:
        return (False, f"錯誤：{str(e)}", [])
    finally:
        conn.close()

def api_take_request(u_id, r_id, time):
    """
    接案 take_request
    Returns: (success: bool, message: str)
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 檢查是否已經接過
            cur.execute("""
                SELECT 1 
                FROM take_request
                WHERE u_id = %s AND r_id = %s
            """, (u_id, r_id))
            if cur.fetchone():
                return (False, "你已經接過這個 request，不能重複接案！")

            # 檢查 r_id 是否 active，並取得資料
            cur.execute("""
                SELECT u_id, status
                FROM user_request
                WHERE r_id = %s
            """, (r_id,))
            row = cur.fetchone()

            if not row:
                return (False, "該 r_id 不存在！")

            owner_u_id, req_status = row

            # 檢查 status
            if req_status != "active":
                return (False, "此 request 目前不是 active 狀態，無法接案")

            # 檢查不能接自己的 request
            if owner_u_id == u_id:
                return (False, "你不能接自己發出的 request")

            if len(time) != 168 or any(c not in "01" for c in time):
                return (False, "time 必須是 168-bit 0/1 字串")

            # 插入 take_request
            cur.execute("""
                INSERT INTO take_request (u_id, r_id, time)
                VALUES (%s, %s, %s)
            """, (u_id, r_id, time))

            conn.commit()
            return (True, f"成功接案！u_id={u_id} 已接下 r_id={r_id}")

    except Exception as e:
        conn.rollback()
        return (False, f"錯誤：{str(e)}")
    finally:
        conn.close()

def api_request_takes(r_id):
    pass


def api_my_take_request(u_id):
    """
    我的接案列表 my_take_request
    Returns: (success: bool, message: str, data: list of dict)
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            sql = """
                SELECT 
                    t.u_id AS taker_uid,
                    t.r_id,
                    t.time AS take_time,
                    r.u_id AS owner_uid,
                    u.username AS owner_username,
                    u.realname AS owner_realname,
                    u.email AS owner_email,
                    r.role,
                    r.target_gradeyear,
                    r.subject,
                    r.request_detail,
                    r.reward,
                    r.place
                FROM take_request t
                JOIN user_request r ON t.r_id = r.r_id
                JOIN "USER" u ON r.u_id = u.u_id
                WHERE t.u_id = %s
                  AND r.status = 'active'
                ORDER BY t.r_id
            """

            cur.execute(sql, (u_id,))
            rows = cur.fetchall()

            if not rows:
                return (True, "你目前沒有 active 的接案紀錄", [])

            results = []
            for row in rows:
                (taker_uid, r_id, take_time,
                 owner_uid, owner_username, owner_realname, owner_email,
                 role, grade_bits, subject, detail, reward, place) = row

                results.append({
                    "taker_uid": taker_uid,
                    "r_id": r_id,
                    "time": take_time,
                    "time_ranges": convert_168bit_to_ranges(take_time),
                    "owner_uid": owner_uid,
                    "owner_username": owner_username,
                    "owner_realname": owner_realname,
                    "owner_email": owner_email,
                    "role": role,
                    "target_gradeyear": grade_bits,
                    "gradeyear_display": convert_grade_bits(grade_bits),
                    "subject": subject,
                    "request_detail": detail,
                    "reward": reward,
                    "place": place
                })

            return (True, f"找到 {len(results)} 筆接案紀錄", results)

    except Exception as e:
        return (False, f"錯誤：{str(e)}", [])
    finally:
        conn.close()

def api_delete_take_request(u_id, r_id):
    """
    刪除接案 delete_take_request
    Returns: (success: bool, message: str)
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 檢查 (u_id, r_id) 是否存在
            cur.execute("""
                SELECT 1
                FROM take_request
                WHERE u_id = %s AND r_id = %s
            """, (u_id, r_id))

            if not cur.fetchone():
                return (False, "找不到該接案紀錄，無法刪除")

            # 真正刪除
            cur.execute("""
                DELETE FROM take_request
                WHERE u_id = %s AND r_id = %s
            """, (u_id, r_id))

            conn.commit()
            return (True, f"成功刪除接案紀錄：u_id={u_id}, r_id={r_id}")

    except Exception as e:
        conn.rollback()
        return (False, f"錯誤：{str(e)}")
    finally:
        conn.close()

def api_my_taken_by(u_id):
    """
    我被接的request
    Returns: (success: bool, message: str, data: list of dict)
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            sql = """
                SELECT 
                    t.u_id AS taker_u_id,
                    u.username AS taker_username,
                    u.realname AS taker_realname,
                    u.email AS taker_email,
                    t.time AS take_time,
                    r.r_id,
                    r.u_id AS owner_u_id,
                    r.role,
                    r.target_gradeyear,
                    r.subject,
                    r.request_detail,
                    r.reward,
                    r.place
                FROM user_request r
                JOIN take_request t ON r.r_id = t.r_id
                JOIN "USER" u ON t.u_id = u.u_id
                WHERE r.u_id = %s
                  AND r.status = 'active'
                ORDER BY r.r_id
            """

            cur.execute(sql, (u_id,))
            rows = cur.fetchall()

            if not rows:
                return (True, "目前沒有任何接案者接你的 request", [])

            results = []
            for row in rows:
                (taker_uid, taker_username, taker_realname, taker_email,
                 take_time, r_id, owner_uid, role, grade_bits,
                 subject, detail, reward, place) = row

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

            return (True, f"找到 {len(results)} 筆接案者", results)

    except Exception as e:
        return (False, f"錯誤：{str(e)}", [])
    finally:
        conn.close()

def api_my_request_taken_by(u_id, r_id):
    """
    我被接的request
    Returns: (success: bool, message: str, data: list of dict)
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            sql = """
                SELECT 
                    t.u_id AS taker_u_id,
                    u.username AS taker_username,
                    u.realname AS taker_realname,
                    u.email AS taker_email,
                    t.time AS take_time,
                    r.r_id,
                    r.u_id AS owner_u_id,
                    r.role,
                    r.target_gradeyear,
                    r.subject,
                    r.request_detail,
                    r.reward,
                    r.place
                FROM user_request r
                JOIN take_request t ON r.r_id = t.r_id
                JOIN "USER" u ON t.u_id = u.u_id
                WHERE r.u_id = %s
                  AND r.status = 'active'
                  AND r.r_id = %s
            """

            cur.execute(sql, (u_id, r_id))
            rows = cur.fetchall()

            if not rows:
                return (True, "目前沒有任何接案者接你的 request", [])

            results = []
            for row in rows:
                (taker_uid, taker_username, taker_realname, taker_email,
                 take_time, r_id, owner_uid, role, grade_bits,
                 subject, detail, reward, place) = row

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

            return (True, f"找到 {len(results)} 筆接案者", results)

    except Exception as e:
        return (False, f"錯誤：{str(e)}", [])
    finally:
        conn.close()

def api_confirm_request_taken_by(u_id_taker, r_id, u_id_owner):
    """
    確認接案者並建立課程
    Returns: (success: bool, message: str, c_id: int or None)
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 檢查 request 是否存在且 active
            cur.execute("""
                SELECT role, u_id, status
                FROM user_request
                WHERE r_id = %s
            """, (r_id,))
            row = cur.fetchone()
            if not row:
                return (False, f"r_id={r_id} 在 user_request 不存在", None)

            role, owner_in_db, status = row

            # 檢查委託人身份
            if owner_in_db != u_id_owner:
                return (False, f"你不是該 request 的委託人，無法確認接案", None)

            if status != "active":
                return (False, f"request status='{status}'，無法建立課程", None)

            # 檢查接案紀錄存在
            cur.execute("""
                SELECT 1
                FROM take_request
                WHERE r_id = %s AND u_id = %s
            """, (r_id, u_id_taker))
            if not cur.fetchone():
                return (False, f"接案紀錄 (u_id={u_id_taker}, r_id={r_id}) 不存在", None)

            # 判斷 teacher / student
            if role == "teacher":
                teacher_u_id = u_id_owner
                student_u_id = u_id_taker
            elif role == "student":
                teacher_u_id = u_id_taker
                student_u_id = u_id_owner
            else:
                return (False, f"未知的 role: {role}", None)

            # 檢查是否已存在相同課程
            cur.execute("""
                SELECT c_id
                FROM course
                WHERE r_id = %s
                  AND teacher_u_id = %s
                  AND student_u_id = %s
            """, (r_id, teacher_u_id, student_u_id))
            existing = cur.fetchone()
            if existing:
                return (False, f"相同課程已存在: c_id={existing[0]}", existing[0])

            # 插入 course
            cur.execute("""
                INSERT INTO course (r_id, teacher_u_id, student_u_id, status)
                VALUES (%s, %s, %s, %s)
                RETURNING c_id
            """, (r_id, teacher_u_id, student_u_id, "ongoing"))
            c_id = cur.fetchone()[0]

            # >>> ★ 新增：刪除接案者的 take_request 記錄
            cur.execute("""
                DELETE FROM take_request
                WHERE r_id = %s AND u_id = %s
            """, (r_id, u_id_taker))
            
            conn.commit()
            return (True, f"成功建立課程: c_id={c_id}, teacher_u_id={teacher_u_id}, student_u_id={student_u_id}", c_id)

    except Exception as e:
        conn.rollback()
        return (False, f"錯誤：{str(e)}", None)
    finally:
        conn.close()

def api_deny_request_taken_by(u_id_taker, r_id, u_id_owner):
    """
    拒絕某人接案request
    Returns: (success: bool, message: str)
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 檢查接案紀錄是否存在
            cur.execute("""
                SELECT 1
                FROM take_request
                WHERE u_id = %s AND r_id = %s
            """, (u_id_taker, r_id))
            if not cur.fetchone():
                return (False, f"接案紀錄 (u_id={u_id_taker}, r_id={r_id}) 不存在")

            # 檢查 request 是否屬於自己
            cur.execute("""
                SELECT u_id
                FROM user_request
                WHERE r_id = %s
            """, (r_id,))
            row = cur.fetchone()
            if not row:
                return (False, f"r_id={r_id} 在 user_request 不存在")

            owner_in_db = row[0]
            if owner_in_db != u_id_owner:
                return (False, f"你不是該 request 的委託人，無法拒絕接案")

            # 刪除 take_request
            cur.execute("""
                DELETE FROM take_request
                WHERE u_id = %s AND r_id = %s
            """, (u_id_taker, r_id))

            conn.commit()
            return (True, f"成功拒絕接案: u_id={u_id_taker}, r_id={r_id}")

    except Exception as e:
        conn.rollback()
        return (False, f"錯誤：{str(e)}")
    finally:
        conn.close()

def api_my_course(u_id):
    """
    查看我的課程
    Returns: (success: bool, message: str, data: dict with 'as_teacher' and 'as_student' lists)
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 你是 Teacher
            cur.execute("""
                SELECT 
                    c.c_id,
                    c.teacher_u_id,
                    c.student_u_id,
                    u.username,
                    u.realname,
                    u.email,
                    r.time,                     
                    r.target_gradeyear,
                    r.subject,
                    r.request_detail,
                    r.reward,    
                    r.place,
                    c.student_score,
                    c.teacher_score
                FROM course c
                JOIN "USER" u ON c.student_u_id = u.u_id
                JOIN user_request r ON r.r_id = c.r_id
                WHERE c.teacher_u_id = %s AND c.status = 'ongoing'
            """, (u_id,))
            rows_teacher = cur.fetchall()

            # 你是 Student
            cur.execute("""
                SELECT 
                    c.c_id,
                    c.student_u_id,
                    c.teacher_u_id,
                    u.username,
                    u.realname,
                    u.email,
                    r.time,
                    r.target_gradeyear,
                    r.subject,
                    r.request_detail,
                    r.reward,
                    r.place,
                    c.student_score,
                    c.teacher_score
                FROM course c
                JOIN "USER" u ON c.teacher_u_id = u.u_id
                JOIN user_request r ON r.r_id = c.r_id
                WHERE c.student_u_id = %s AND c.status = 'ongoing'
            """, (u_id,))
            rows_student = cur.fetchall()

            # 格式化 Teacher
            teacher_courses = []
            for row in rows_teacher:
                (c_id, teacher_uid, student_uid,
                 username, realname, email,
                 take_time, grade_bits,
                 subject, detail, reward, place,
                 student_score, teacher_score) = row

                time_str = "No time"
                if take_time:
                    time_str = convert_168bit_to_ranges(take_time)

                teacher_courses.append({
                    "c_id": c_id,
                    "teacher_u_id": teacher_uid,
                    "student_u_id": student_uid,
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
                    "role": "teacher",
                })

            # 格式化 Student
            student_courses = []
            for row in rows_student:
                (c_id, student_uid, teacher_uid,
                 username, realname, email,
                 take_time, grade_bits,
                 subject, detail, reward, place,
                 student_score, teacher_score) = row

                time_str = "No time"
                if take_time:
                    time_str = convert_168bit_to_ranges(take_time)

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

            return (True, f"找到 {len(teacher_courses)} 個作為教師的課程, {len(student_courses)} 個作為學生的課程", teacher_courses + student_courses)

    except Exception as e:
        return (False, f"錯誤：{str(e)}", [])
    finally:
        conn.close()

def api_rate_course(u_id, c_id, score):
    """
    評分課程
    Returns: (success: bool, message: str)
    """
    # 基本輸入檢查
    try:
        score = int(score)
        if not (1 <= score <= 5):
            return (False, "score 必須介於 1~5")
    except ValueError:
        return (False, "score 必須是數字")

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 查詢該課程
            cur.execute("""
                SELECT teacher_u_id, student_u_id
                FROM course
                WHERE c_id = %s
            """, (c_id,))
            row = cur.fetchone()

            if not row:
                return (False, "查無此 c_id 的課程")

            teacher_u_id, student_u_id = row

            # 判斷使用者身份
            if u_id == teacher_u_id:
                # Teacher 評 Student
                cur.execute("""
                    UPDATE course
                    SET student_score = %s
                    WHERE c_id = %s
                """, (score, c_id))
                conn.commit()
                return (True, f"成功！你已給 Student 評分：{score}")

            elif u_id == student_u_id:
                # Student 評 Teacher
                cur.execute("""
                    UPDATE course
                    SET teacher_score = %s
                    WHERE c_id = %s
                """, (score, c_id))
                conn.commit()
                return (True, f"成功！你已給 Teacher 評分：{score}")

            else:
                return (False, "你不是這門課程的成員，無法評分")

    except Exception as e:
        conn.rollback()
        return (False, f"錯誤：{str(e)}")
    finally:
        conn.close()

# ==================== ADMIN API FUNCTIONS ====================

def is_admin(u_id):
    """
    檢查是否為管理員
    Returns: bool
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT role
                FROM "USER"
                WHERE u_id = %s
                AND status = 'active'
            """, (u_id,))
            row = cur.fetchone()

            if not row:
                return False

            role = row[0]
            return role == "admin"

    except Exception:
        return False
    finally:
        conn.close()

def api_admin_search_user(admin_u_id, u_id):
    """
    管理員搜尋使用者
    Returns: (success: bool, message: str, data: dict or None)
    """
    if not is_admin(admin_u_id):
        return (False, "權限錯誤：你不是管理員，無法使用此功能", None)
    
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT u_id, username, realname, email, role, status
                FROM "USER"
                WHERE u_id = %s
            """, (u_id,))
            row = cur.fetchone()

            if not row:
                return (False, "查無此使用者", None)

            u_id_val, username, realname, email, role, status = row
            return (True, "查詢成功", {
                "u_id": u_id_val,
                "username": username,
                "realname": realname,
                "email": email,
                "role": role,
                "status": status
            })

    except Exception as e:
        return (False, f"錯誤：{str(e)}", None)
    finally:
        conn.close()


def api_admin_edit_user_role(admin_u_id, target_u_id, new_role):
    """
    管理員修改使用者角色
    Returns: (success: bool, message: str)
    """
    if new_role not in ("user", "admin"):
        return (False, "角色只能是 'user' 或 'admin'")

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 檢查管理員權限（可選）
            cur.execute("""
                SELECT role FROM "USER" WHERE u_id = %s
            """, (admin_u_id,))
            admin_row = cur.fetchone()
            if not admin_row:
                return (False, "管理員帳號不存在")
            
            # 確認使用者是否存在
            cur.execute("""
                SELECT u_id FROM "USER" WHERE u_id = %s
            """, (target_u_id,))
            row = cur.fetchone()

            if not row:
                return (False, "查無此使用者")

            # 更新角色
            cur.execute("""
                UPDATE "USER"
                SET role = %s
                WHERE u_id = %s
            """, (new_role, target_u_id))
            conn.commit()

            return (True, f"成功！u_id = {target_u_id} 的角色已更新為 {new_role}")

    except Exception as e:
        conn.rollback()
        return (False, f"錯誤：{str(e)}")
    finally:
        conn.close()


def api_admin_edit_user_password(admin_u_id, target_u_id, new_password):
    """
    管理員修改使用者密碼
    Returns: (success: bool, message: str)
    """
    if not new_password:
        return (False, "新密碼不能為空")

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 檢查管理員權限（可選）
            cur.execute("""
                SELECT role FROM "USER" WHERE u_id = %s
            """, (admin_u_id,))
            admin_row = cur.fetchone()
            if not admin_row:
                return (False, "管理員帳號不存在")
            
            # 確認使用者是否存在
            cur.execute("""
                SELECT u_id FROM "USER" WHERE u_id = %s
            """, (target_u_id,))
            row = cur.fetchone()

            if not row:
                return (False, "查無此使用者")

            # 更新密碼
            hashed_new_password = hash_password(new_password)
            cur.execute("""
                UPDATE "USER"
                SET password = %s
                WHERE u_id = %s
            """, (hashed_new_password, target_u_id))
            conn.commit()

            return (True, f"成功！u_id = {target_u_id} 的密碼已更新")

    except Exception as e:
        conn.rollback()
        return (False, f"錯誤：{str(e)}")
    finally:
        conn.close()

def api_admin_suspend_user(admin_u_id, target_u_id):
    """
    管理員停權使用者
    Returns: (success: bool, message: str)
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 檢查管理者是否存在
            cur.execute("""
                SELECT u_id, role, status
                FROM "USER"
                WHERE u_id = %s
            """, (admin_u_id,))
            admin_row = cur.fetchone()

            if not admin_row:
                return (False, "你的 u_id 不存在，無法操作")

            # 查詢被停權者資訊
            cur.execute("""
                SELECT u_id, role, status
                FROM "USER"
                WHERE u_id = %s
            """, (target_u_id,))
            row = cur.fetchone()

            if not row:
                return (False, "查無要停權的使用者")

            _, role, status = row

            # 檢查角色是否為 user
            if role != "user":
                return (False, f"無法停權！該使用者角色為 {role}（僅 role='user' 可停權）")

            # 停權並記錄 delete_by
            cur.execute("""
                UPDATE "USER"
                SET status = 'suspended', delete_by = %s
                WHERE u_id = %s
            """, (admin_u_id, target_u_id))
            conn.commit()

            return (True, f"成功！u_id = {target_u_id} 已被停權")

    except Exception as e:
        conn.rollback()
        return (False, f"錯誤：{str(e)}")
    finally:
        conn.close()

def api_admin_search_request(admin_u_id, r_id=None, u_id=None):
    """
    管理員搜尋 request
    Returns: (success: bool, message: str, data: list of dict)
    """
    if not is_admin(admin_u_id):
        return (False, "權限錯誤：你不是管理員，無法使用此功能", [])

    if not r_id and not u_id:
        return (False, "錯誤：r_id 與 u_id 不可同時為空！", [])

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            conditions = []
            params = []

            if r_id:
                conditions.append("r_id = %s")
                params.append(r_id)

            if u_id:
                conditions.append("u_id = %s")
                params.append(u_id)

            where_clause = " AND ".join(conditions)
            where_clause = "WHERE " + where_clause

            cur.execute(f"""
                SELECT 
                    r_id, u_id, role, target_gradeyear, subject,
                    request_detail, reward, place, time, status
                FROM user_request
                {where_clause}
                ORDER BY r_id
            """, tuple(params))

            rows = cur.fetchall()

            if not rows:
                return (True, "查無符合條件的 request", [])

            results = []
            for row in rows:
                (r_id_val, u_id_val, role, grade_bits, subject,
                 request_detail, reward, place, bit168, status) = row

                results.append({
                    "r_id": r_id_val,
                    "u_id": u_id_val,
                    "role": role,
                    "target_gradeyear": grade_bits,
                    "gradeyear_display": convert_grade_bits(grade_bits),
                    "subject": subject,
                    "request_detail": request_detail,
                    "reward": reward,
                    "place": place,
                    "time": bit168,
                    "time_ranges": convert_168bit_to_ranges(bit168),
                    "status": status
                })

            return (True, f"找到 {len(results)} 筆 request", results)

    except Exception as e:
        return (False, f"錯誤：{str(e)}", [])
    finally:
        conn.close()

def api_admin_delete_request(admin_u_id, r_id):
    """
    管理員刪除 request
    Returns: (success: bool, message: str)
    """

    if not is_admin(admin_u_id):
        return (False, "權限錯誤：你不是管理員，無法使用此功能")

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 檢查 r_id 是否存在
            cur.execute("""
                SELECT r_id, status
                FROM user_request
                WHERE r_id = %s
            """, (r_id,))
            req_row = cur.fetchone()

            if not req_row:
                return (False, f"找不到 r_id = {r_id} 的 request")

            # 更新 status 與 delete_by
            cur.execute("""
                UPDATE user_request
                SET status = 'deleted', delete_by = %s
                WHERE r_id = %s
            """, (admin_u_id, r_id))
            conn.commit()

            return (True, f"成功！r_id = {r_id} 已被刪除")

    except Exception as e:
        conn.rollback()
        return (False, f"錯誤：{str(e)}")
    finally:
        conn.close()

def api_admin_search_take_request(admin_u_id, r_id=None, u_id=None):
    """
    管理員搜尋 take_request
    Returns: (success: bool, message: str, data: list of dict)
    """
    if not is_admin(admin_u_id):
        return (False, "權限錯誤：你不是管理員，無法使用此功能", [])

    if not r_id and not u_id:
        return (False, "錯誤：r_id 與接案人 u_id 不可同時為空！", [])

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            conditions = []
            params = []

            if r_id:
                conditions.append("r_id = %s")
                params.append(r_id)

            if u_id:
                conditions.append("u_id = %s")
                params.append(u_id)

            where_clause = " AND ".join(conditions)
            where_clause = "WHERE " + where_clause

            cur.execute(f"""
                SELECT r_id, u_id, time
                FROM take_request
                {where_clause}
                ORDER BY r_id
            """, tuple(params))

            rows = cur.fetchall()

            if not rows:
                return (True, "查無符合條件的 take_request", [])

            results = []
            for row in rows:
                r_id_val, u_id_val, bit168 = row

                results.append({
                    "r_id": r_id_val,
                    "u_id": u_id_val,
                    "time": bit168,
                    "time_ranges": convert_168bit_to_ranges(bit168)
                })

            return (True, f"找到 {len(results)} 筆 take_request", results)

    except Exception as e:
        return (False, f"錯誤：{str(e)}", [])
    finally:
        conn.close()

def api_admin_delete_take_request(admin_u_id, r_id, u_id):
    """
    管理員刪除 take_request
    Returns: (success: bool, message: str)
    """
    if not is_admin(admin_u_id):
        return (False, "權限錯誤：你不是管理員，無法使用此功能")
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 檢查是否存在該筆 take_request
            cur.execute("""
                SELECT r_id
                FROM take_request
                WHERE r_id = %s AND u_id = %s
            """, (r_id, u_id))
            row = cur.fetchone()

            if not row:
                return (False, "找不到符合條件的 take_request！")

            # 刪除紀錄
            cur.execute("""
                DELETE FROM take_request
                WHERE r_id = %s AND u_id = %s
            """, (r_id, u_id))
            conn.commit()

            return (True, f"成功刪除 take_request：r_id = {r_id}, u_id = {u_id}")

    except Exception as e:
        conn.rollback()
        return (False, f"錯誤：{str(e)}")
    finally:
        conn.close()

def api_admin_search_course(admin_u_id, c_id):
    """
    管理員搜尋 course
    Returns: (success: bool, message: str, data: dict or None)
    """
    if not is_admin(admin_u_id):
        return (False, "權限錯誤：你不是管理員，無法使用此功能", None)
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT c_id, r_id, student_u_id, teacher_u_id, 
                       student_score, teacher_score, status
                FROM course
                WHERE c_id = %s
            """, (c_id,))

            row = cur.fetchone()

            if not row:
                return (False, f"找不到 c_id = {c_id} 的課程", None)

            (c_id_val, r_id_val, student_uid, teacher_uid,
             student_score, teacher_score, status) = row

            return (True, "查詢成功", {
                "c_id": c_id_val,
                "r_id": r_id_val,
                "student_u_id": student_uid,
                "teacher_u_id": teacher_uid,
                "student_score": student_score,
                "teacher_score": teacher_score,
                "status": status
            })

    except Exception as e:
        return (False, f"錯誤：{str(e)}", None)
    finally:
        conn.close()

def api_admin_delete_course(admin_u_id, c_id):
    """
    管理員刪除 course
    Returns: (success: bool, message: str)
    """
    if not is_admin(admin_u_id):
        return (False, "權限錯誤：你不是管理員，無法使用此功能")
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 檢查課程是否存在
            cur.execute("""
                SELECT c_id, status
                FROM course
                WHERE c_id = %s
            """, (c_id,))
            course_row = cur.fetchone()
            if not course_row:
                return (False, f"找不到 c_id = {c_id} 的課程")

            # 更新課程狀態與 delete_by
            cur.execute("""
                UPDATE course
                SET status = 'deleted', delete_by = %s
                WHERE c_id = %s
            """, (admin_u_id, c_id))
            conn.commit()

            return (True, f"成功！c_id = {c_id} 的課程已被標記為 deleted")

    except Exception as e:
        conn.rollback()
        return (False, f"錯誤：{str(e)}")
    finally:
        conn.close()

def api_admin_reset_course_rate(admin_u_id, c_id):
    """
    管理員重置課程評分
    Returns: (success: bool, message: str)
    """
    if not is_admin(admin_u_id):
        return (False, "權限錯誤：你不是管理員，無法使用此功能")
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 檢查課程是否存在
            cur.execute("""
                SELECT c_id
                FROM course
                WHERE c_id = %s
            """, (c_id,))
            course_row = cur.fetchone()
            if not course_row:
                return (False, f"找不到 c_id = {c_id} 的課程")

            # 將評分設為 NULL
            cur.execute("""
                UPDATE course
                SET student_score = NULL,
                    teacher_score = NULL
                WHERE c_id = %s
            """, (c_id,))
            conn.commit()

            return (True, f"成功！c_id = {c_id} 的評分已重置")

    except Exception as e:
        conn.rollback()
        return (False, f"錯誤：{str(e)}")
    finally:
        conn.close()

# ==================== ORIGINAL CLI FUNCTIONS (unchanged) ====================
'''
# ------------------ Service Layer ------------------
    #--------------signup--&--login---------------
def sign_up():
    print("\n=== 使用者註冊 ===")
    username = input("輸入 username: ").strip()
    password = input("輸入 password: ").strip()
    confirm_password = input("確認 password: ").strip()
    realname = input("輸入 realname: ").strip()
    email = input("輸入 email: ").strip()

    if not all([username, password, confirm_password, realname, email]):
        print("所有欄位都必填！")
        return

    if password != confirm_password:
        print("密碼與確認密碼不一致！")
        return
    
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 檢查 username
            cur.execute('SELECT COUNT(*) FROM "USER" WHERE username=%s', (username,))
            if cur.fetchone()[0] > 0:
                print("username 已存在！")
                return

            # 檢查 realname
            cur.execute('SELECT COUNT(*) FROM "USER" WHERE realname=%s', (realname,))
            if cur.fetchone()[0] > 0:
                print("realname 已存在！")
                return

            # 檢查 email
            cur.execute('SELECT COUNT(*) FROM "USER" WHERE email=%s', (email,))
            if cur.fetchone()[0] > 0:
                print("email 已存在！")
                return
            
            # 執行signup
            cur.execute(
                'INSERT INTO "USER" (username, password, realname, email,role,status) VALUES (%s, %s, %s, %s,%s,%s)',
                (username, password, realname, email,'user','active')
            )
            conn.commit()
            print("註冊成功！")
    except Exception as e:
        print("錯誤：", e)
        conn.rollback()
    finally:
        conn.close()

def login():
    print("\n=== 使用者登入 ===")
    username = input("輸入 username: ").strip()
    password = input("輸入 password: ").strip()

    if not username or not password:
        print("帳號密碼不可為空")
        return

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 查 role + status
            cur.execute(
                """
                SELECT role, status 
                FROM "USER" 
                WHERE username = %s AND password = %s
                """,
                (username, password)
            )
            result = cur.fetchone()

            if not result:
                print("帳號或密碼錯誤！")
                return

            role, status = result

            # ---- 加入 status 檢查 ----
            if status != "active":
                print(f"登入失敗！你的帳號目前狀態為 {status}，無法登入。")
                return

            print(f"登入成功！使用者角色：{role}")

    except Exception as e:
        print("錯誤：", e)

    finally:
        conn.close()
    
    #----------------user功能----------------
def edit_password():
    print("\n=== 修改密碼 ===")
    username = input("輸入 username: ").strip()
    realname = input("輸入 realname: ").strip()
    old_password = input("輸入目前password: ").strip()
    new_password = input("輸入新password: ").strip()

    if not all([username, realname, old_password ,new_password]):
        print("欄位不可為空！")
        return

    conn = get_connection()
    try:
        with conn.cursor() as cur:

            # 檢查 username + realname 是否一致
            cur.execute(
                'SELECT COUNT(*) FROM "USER" WHERE username=%s AND password=%s AND realname=%s',
                (username,old_password ,realname)
            )
            if cur.fetchone()[0] == 0:
                print("找不到符合的使用者，無法修改密碼！")
                return

            # 更新密碼
            cur.execute(
                'UPDATE "USER" SET password=%s WHERE username=%s AND realname=%s',
                (new_password, username, realname)
            )
            conn.commit()
            print("密碼修改成功！")

    except Exception as e:
        print("錯誤：", e)
        conn.rollback()
    finally:
        conn.close()

def delete_account():
    print("\n=== 刪除帳號（標記刪除） ===")
    username = input("輸入 username: ").strip()
    password = input("輸入 password: ").strip()
    realname = input("輸入 realname: ").strip()

    if not all([username, password, realname]):
        print("所有欄位都必填！")
        return

    conn = get_connection()
    try:
        with conn.cursor() as cur:

            # 驗證使用者是否存在
            cur.execute(
                'SELECT u_id FROM "USER" WHERE username=%s AND password=%s AND realname=%s AND status != %s',
                (username, password, realname, "deleted")
            )
            result = cur.fetchone()

            if not result:
                print("使用者不存在或資料不正確！")
                return

            user_id = result[0]  # 刪除者 = 自己的 u_id

            # 更新使用者狀態
            cur.execute(
                'UPDATE "USER" SET status=%s, delete_by=%s WHERE u_id=%s',
                ("deleted", user_id, user_id)
            )
            conn.commit()

            print(f"帳號已刪除")

    except Exception as e:
        print("錯誤：", e)
        conn.rollback()
    finally:
        conn.close()

def post_request():
    print("\n=== 發佈新課程請求 ===")
    
    # ---- 使用者輸入 ----
    u_id = input("輸入你的 u_id: ").strip()
    role = input("輸入你的角色 (teacher/student): ").strip().lower()
    target_gradeyear = input("輸入 target_gradeyear (8-bit 整數): ").strip()
    subject = input("輸入科目: ").strip()
    request_detail = input("輸入課程需求: ").strip()
    reward = input("輸入每小時費用: ").strip()
    place = input("輸入地點: ").strip()

    # ---- 基本檢查 ----
    if not u_id.isdigit():
        print("u_id 必須為整數")
        return
    u_id = int(u_id)

    if role not in ("teacher", "student"):
        print("角色必須是 teacher 或 student")
        return

    if len(target_gradeyear) != 8 or any(c not in "01" for c in target_gradeyear):
        print("target_gradeyear 必須是 8-bit 0/1 字串")
        return

    if not reward.isdigit():
        print("reward 必須是整數")
        return
    reward = int(reward)

    # ---- 預設 time: 1 個 1 + 167 個 0 ----
    default_time_bits = "1" + "0" * 167

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO user_request
                    (u_id, role, target_gradeyear, subject, request_detail, reward, place, time, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'active')
                RETURNING r_id
            """, (u_id, role, target_gradeyear, subject, request_detail, reward, place, default_time_bits))
            
            r_id = cur.fetchone()[0]
            conn.commit()
            print(f"課程請求已新增成功，r_id = {r_id}")

    except Exception as e:
        print("錯誤：", e)
    finally:
        conn.close()


def my_request():
    print("\n=== 查看自己的 request ===")
    try:
        u_id = int(input("輸入 u_id: ").strip())
    except ValueError:
        print("u_id 必須是整數！")
        return

    conn = get_connection()
    try:
        with conn.cursor() as cur:

            # 取得所有 active request，加入 target_gradeyear 欄位
            cur.execute(
                """
                SELECT r_id, u_id, time, role, subject, target_gradeyear,
                       request_detail, reward, place
                FROM user_request
                WHERE u_id=%s AND status=%s
                """,
                (u_id, "active")
            )

            rows = cur.fetchall()

            if not rows:
                print("查無 active request")
                return

            formatted_rows = []
            for r in rows:
                (r_id, u_id, bit168, role, subject, grade_bits,
                 request_detail, reward, place) = r

                # 解析 168-bit 時間
                ranges = convert_168bit_to_ranges(bit168)
                ranges_str = "\n".join(ranges)

                # 解析 8-bit 年級
                grade_str = convert_grade_bits(grade_bits)

                formatted_rows.append([
                    r_id,
                    u_id,
                    ranges_str,
                    role,
                    subject,
                    grade_str,         # ★ 新增
                    request_detail,
                    reward,
                    place
                ])

            headers = [
                "r_id",
                "u_id",
                "time",
                "role(委託人)",
                "subject",
                "gradeyear",       # ★ 新增欄位
                "request_detail",
                "reward(per hour)",
                "place"
            ]
            print(tabulate(formatted_rows, headers=headers, tablefmt="psql"))

    except Exception as e:
        print("錯誤：", e)
    finally:
        conn.close()

def edit_request():
    print("未完成")

def delete_request():
    print("\n=== 刪除 Request ===")

    try:
        u_id = int(input("輸入 u_id: ").strip())
        r_id = int(input("輸入 r_id: ").strip())
    except ValueError:
        print("u_id 和 r_id 必須是整數！")
        return

    conn = get_connection()
    try:
        with conn.cursor() as cur:

            # (1) 檢查 r_id 存不存在 + 是否屬於該 u_id
            cur.execute(
                """
                SELECT u_id FROM user_request
                WHERE r_id = %s AND status != %s
                """,
                (r_id, "deleted")
            )

            row = cur.fetchone()

            if not row:
                print("找不到該 r_id")
                return

            owner_u_id = row[0]

            if owner_u_id != u_id:
                print("權限錯誤：該 request 不屬於此 u_id，無法刪除！")
                return

            # (2) 執行刪除（標記 deleted）
            cur.execute(
                """
                UPDATE user_request
                SET status=%s, delete_by=%s
                WHERE r_id=%s
                """,
                ("deleted", u_id, r_id)
            )

            conn.commit()
            print(f"Request {r_id} 已刪除")

    except Exception as e:
        print("錯誤：", e)
        conn.rollback()
    finally:
        conn.close()

def search_request():
    print("\n=== 搜尋 Request(可部分搜尋) ===")

    role = input("找student or teacher?: ").strip()
    subject = input("subject: ").strip()
    target_bits = input("gradeyear (8bit): ").strip()
    request_detail = input("request_detail: ").strip()
    reward = input("reward(最低時薪): ").strip()
    place = input("place: ").strip()

    conn = get_connection()
    try:
        with conn.cursor() as cur:

            # 基本 SQL + JOIN USER
            sql = """
                SELECT 
                    r.r_id,
                    r.u_id,
                    u.username,
                    u.realname,
                    u.email,
                    r.time,
                    r.role,
                    r.subject,
                    r.target_gradeyear,
                    r.request_detail,
                    r.reward,
                    r.place
                FROM user_request r
                JOIN "USER" u ON r.u_id = u.u_id
                WHERE r.status='active'
            """

            params = []

            # --- 動態條件（若輸入空就略過） ---
            if role:
                sql += " AND r.role = %s"
                params.append(role)

            if subject:
                sql += " AND r.subject ILIKE %s"
                params.append(f"%{subject}%")

            if request_detail:
                sql += " AND r.request_detail ILIKE %s"
                params.append(f"%{request_detail}%")

            if place:
                sql += " AND r.place ILIKE %s"
                params.append(f"%{place}%")

            if reward:
                try:
                    reward_val = int(reward)
                    sql += " AND r.reward >= %s"
                    params.append(reward_val)
                except:
                    print("reward 必須是整數或空")
                    return

            # --- target_gradeyear（8bit AND 檢查是否有重疊） ---
            if target_bits:
                if len(target_bits) != 8 or any(c not in "01" for c in target_bits):
                    print("target_gradeyear 必須是 8 個 bit")
                    return

                subconds = []
                for i in range(8):
                    if target_bits[i] == "1":
                        subconds.append(f"substring(r.target_gradeyear from {i+1} for 1) = '1'")

                if subconds:
                    sql += " AND (" + " OR ".join(subconds) + ")"

            # --- 最後排序 + LIMIT ---
            sql += " ORDER BY r.reward ASC LIMIT 10"

            cur.execute(sql, tuple(params))
            rows = cur.fetchall()

            if not rows:
                print("查無符合的 request")
                return

            # --- 整理輸出 ---
            formatted_rows = []
            for r in rows:
                (r_id, u_id, username, realname, email,
                 bit168, role, subject, grade_bits,
                 request_detail, reward, place) = r

                # 解析 168bit → 星期幾區段
                time_ranges = convert_168bit_to_ranges(bit168)
                time_str = "\n".join(time_ranges)

                # 解析 8bit → "1, 3, 5 年級"
                grade_str = convert_grade_bits(grade_bits)

                formatted_rows.append([
                    r_id,
                    u_id,
                    username,
                    realname,
                    email,
                    time_str,
                    role,
                    subject,
                    grade_str,
                    request_detail,
                    reward,
                    place
                ])

            headers = [
                "r_id",
                "u_id",
                "username",
                "realname",
                "email",
                "time",
                "role(委託人)",
                "subject",
                "gradeyear",
                "request_detail",
                "reward(per hour)",
                "place"
            ]

            print(tabulate(formatted_rows, headers=headers, tablefmt="psql"))

    except Exception as e:
        print("錯誤：", e)
    finally:
        conn.close()

def take_request():
    print("\n=== 接案 take_request ===")

    u_id = input("輸入你的 u_id: ").strip()
    r_id = input("輸入 r_id: ").strip()

    if not u_id.isdigit() or not r_id.isdigit():
        print("u_id 與 r_id 必須是整數")
        return

    u_id = int(u_id)
    r_id = int(r_id)

    conn = get_connection()
    try:
        with conn.cursor() as cur:

            # 0. 檢查是否已經接過
            cur.execute("""
                SELECT 1 
                FROM take_request
                WHERE u_id = %s AND r_id = %s
            """, (u_id, r_id))
            if cur.fetchone():
                print("你已經接過這個 request，不能重複接案！")
                return

            # 1. 檢查 r_id 是否 active，並取得資料
            cur.execute("""
                SELECT u_id, time, status
                FROM user_request
                WHERE r_id = %s
            """, (r_id,))
            row = cur.fetchone()

            if not row:
                print("該 r_id 不存在！")
                return

            owner_u_id, req_time, status = row

            # 2. 檢查 status
            if status != "active":
                print("此 request 目前不是 active 狀態，無法接案")
                return

            # 3. 檢查不能接自己的 request
            if owner_u_id == u_id:
                print("你不能接自己發出的 request")
                return

            # 4. 插入 take_request（依你資料表結構插入）
            cur.execute("""
                INSERT INTO take_request (u_id, r_id, time)
                VALUES (%s, %s, %s)
            """, (u_id, r_id, req_time))

            conn.commit()
            print(f"成功接案！u_id={u_id} 已接下 r_id={r_id}")

    except Exception as e:
        print("錯誤：", e)
        conn.rollback()
    finally:
        conn.close()

def my_take_request():
    print("\n=== 我的接案列表 my_take_request ===")

    u_id = input("輸入你的 u_id: ").strip()
    if not u_id.isdigit():
        print("u_id 必須是整數")
        return
    u_id = int(u_id)

    conn = get_connection()
    try:
        with conn.cursor() as cur:

            sql = """
                SELECT 
                    t.u_id AS taker_uid,            -- 接案者(自己)
                    t.r_id,
                    t.time AS take_time,

                    r.u_id AS owner_uid,            -- 委託人 id
                    u.username AS owner_username,   -- 委託人資料(從 USER)
                    u.realname AS owner_realname,
                    u.email AS owner_email,

                    r.role,
                    r.target_gradeyear,
                    r.subject,
                    r.request_detail,
                    r.reward,
                    r.place

                FROM take_request t
                JOIN user_request r ON t.r_id = r.r_id
                JOIN "USER" u ON r.u_id = u.u_id   -- 加入委託人資料
                WHERE t.u_id = %s
                  AND r.status = 'active'
                ORDER BY t.r_id
            """

            cur.execute(sql, (u_id,))
            rows = cur.fetchall()

            if not rows:
                print("你目前沒有 active 的接案紀錄")
                return

            formatted_rows = []
            for row in rows:
                (taker_uid, r_id, take_time,
                 owner_uid, owner_username, owner_realname, owner_email,
                 role, grade_bits, subject, detail, reward, place) = row

                # 解析 168bit time
                time_ranges = convert_168bit_to_ranges(take_time)
                time_str = "\n".join(time_ranges)

                # 解析 8bit 年級
                grade_str = convert_grade_bits(grade_bits)

                formatted_rows.append([
                    taker_uid,
                    r_id,
                    time_str,

                    owner_uid,
                    owner_username,
                    owner_realname,
                    owner_email,

                    role,
                    grade_str,
                    subject,
                    detail,
                    reward,
                    place
                ])

            headers = [
                "u_id(自己)",
                "r_id",
                "time",

                "u_id(委託人)",
                "username",
                "realname",
                "email",

                "role(委託人)",
                "target_grade",
                "subject",
                "request_detail",
                "reward",
                "place"
            ]

            print(tabulate(formatted_rows, headers=headers, tablefmt="psql"))

    except Exception as e:
        print("錯誤：", e)
    finally:
        conn.close()

def delete_take_request():
    print("\n=== 刪除接案 delete_take_request ===")

    u_id = input("輸入你的 u_id: ").strip()
    r_id = input("輸入 r_id: ").strip()

    if not u_id.isdigit() or not r_id.isdigit():
        print("u_id 與 r_id 必須是整數")
        return

    u_id = int(u_id)
    r_id = int(r_id)

    conn = get_connection()
    try:
        with conn.cursor() as cur:

            # 1. 檢查 (u_id, r_id) 是否存在
            cur.execute("""
                SELECT 1
                FROM take_request
                WHERE u_id = %s AND r_id = %s
            """, (u_id, r_id))

            if not cur.fetchone():
                print("找不到該接案紀錄，無法刪除")
                return

            # 2. 真正刪除
            cur.execute("""
                DELETE FROM take_request
                WHERE u_id = %s AND r_id = %s
            """, (u_id, r_id))

            conn.commit()
            print(f"成功刪除接案紀錄：u_id={u_id}, r_id={r_id}")

    except Exception as e:
        print("錯誤：", e)
        conn.rollback()
    finally:
        conn.close()

def my_request_taken_by():
    print("\n=== 我被接的request ===")

    owner_u_id = input("輸入你的 u_id: ").strip()
    if not owner_u_id.isdigit():
        print("u_id 必須是整數")
        return
    owner_u_id = int(owner_u_id)

    conn = get_connection()
    try:
        with conn.cursor() as cur:

            sql = """
                SELECT 
                    t.u_id AS taker_u_id,
                    u.username AS taker_username,
                    u.realname AS taker_realname,
                    u.email AS taker_email,
                    t.time AS take_time,
                    r.r_id,
                    r.u_id AS owner_u_id,
                    r.role,
                    r.target_gradeyear,
                    r.subject,
                    r.request_detail,
                    r.reward,
                    r.place
                FROM user_request r
                JOIN take_request t ON r.r_id = t.r_id
                JOIN "USER" u ON t.u_id = u.u_id
                WHERE r.u_id = %s
                  AND r.status = 'active'
                ORDER BY r.r_id
            """

            cur.execute(sql, (owner_u_id,))
            rows = cur.fetchall()

            if not rows:
                print("目前沒有任何接案者接你的 request")
                return

            formatted_rows = []
            for row in rows:
                (taker_uid, taker_username, taker_realname, taker_email,
                 take_time, r_id, owner_uid, role, grade_bits,
                 subject, detail, reward, place) = row

                # 解析 168bit time
                time_ranges = convert_168bit_to_ranges(take_time)
                time_str = "\n".join(time_ranges)

                # 解析 8bit 年級
                grade_str = convert_grade_bits(grade_bits)

                formatted_rows.append([
                    taker_uid,
                    taker_username,
                    taker_realname,
                    taker_email,
                    time_str,
                    r_id,
                    owner_uid,
                    role,
                    grade_str,
                    subject,
                    detail,
                    reward,
                    place
                ])

            headers = [
                "u_id(接案人)",
                "username",
                "realname",
                "email",
                "time",
                "r_id",
                "u_id(自己)(委託人)",
                "role(委託人)",
                "gradeyear",
                "subject",
                "request_detail",
                "reward",
                "place"
            ]

            print(tabulate(formatted_rows, headers=headers, tablefmt="psql"))

    except Exception as e:
        print("錯誤：", e)
    finally:
        conn.close()

def confirm_request_taken_by():
    print("\n=== 確認接案者並建立課程 ===")

    u_id_taker = input("輸入接案者 u_id: ").strip()
    r_id = input("輸入 r_id: ").strip()
    u_id_owner = input("輸入自己的 u_id: ").strip()

    if not (u_id_taker.isdigit() and r_id.isdigit() and u_id_owner.isdigit()):
        print("所有輸入都必須是整數")
        return

    u_id_taker = int(u_id_taker)
    r_id = int(r_id)
    u_id_owner = int(u_id_owner)

    conn = get_connection()
    try:
        with conn.cursor() as cur:

            # 1. 檢查 request 是否存在且 active
            cur.execute("""
                SELECT role, u_id, status
                FROM user_request
                WHERE r_id = %s
            """, (r_id,))
            row = cur.fetchone()
            if not row:
                print(f"r_id={r_id} 在 user_request 不存在")
                return

            role, owner_in_db, status = row

            # 2. 檢查委託人身份
            if owner_in_db != u_id_owner:
                print(f"你不是該 request 的委託人，無法確認接案")
                return

            if status != "active":
                print(f"request status='{status}'，無法建立課程")
                return

            # 3. 檢查接案紀錄存在
            cur.execute("""
                SELECT 1
                FROM take_request
                WHERE r_id = %s AND u_id = %s
            """, (r_id, u_id_taker))
            if not cur.fetchone():
                print(f"接案紀錄 (u_id={u_id_taker}, r_id={r_id}) 不存在")
                return

            # 4. 判斷 teacher / student
            if role == "teacher":
                teacher_u_id = u_id_owner
                student_u_id = u_id_taker
            elif role == "student":
                teacher_u_id = u_id_taker
                student_u_id = u_id_owner
            else:
                print(f"未知的 role: {role}")
                return

            # 5. 檢查是否已存在相同課程
            cur.execute("""
                SELECT 1
                FROM course
                WHERE r_id = %s
                  AND teacher_u_id = %s
                  AND student_u_id = %s
            """, (r_id, teacher_u_id, student_u_id))
            if cur.fetchone():
                print(f"相同課程已存在: r_id={r_id}, teacher_u_id={teacher_u_id}, student_u_id={student_u_id}")
                return

            # 6. 插入 course
            cur.execute("""
                INSERT INTO course (r_id, teacher_u_id, student_u_id, status)
                VALUES (%s, %s, %s, %s)
            """, (r_id, teacher_u_id, student_u_id, "ongoing"))

            conn.commit()
            print(f"成功建立課程: r_id={r_id}, teacher_u_id={teacher_u_id}, student_u_id={student_u_id}, status='ongoing'")

    except Exception as e:
        print("錯誤：", e)
        conn.rollback()
    finally:
        conn.close()

def deny_request_taken_by():
    print("\n=== 拒絕某人接案request ===")

    u_id_taker = input("輸入接案者 u_id: ").strip()
    r_id = input("輸入 r_id: ").strip()
    u_id_owner = input("輸入你自己的 u_id (委託人): ").strip()

    if not (u_id_taker.isdigit() and r_id.isdigit() and u_id_owner.isdigit()):
        print("所有輸入都必須是整數")
        return

    u_id_taker = int(u_id_taker)
    r_id = int(r_id)
    u_id_owner = int(u_id_owner)

    conn = get_connection()
    try:
        with conn.cursor() as cur:

            # 1. 檢查接案紀錄是否存在
            cur.execute("""
                SELECT 1
                FROM take_request
                WHERE u_id = %s AND r_id = %s
            """, (u_id_taker, r_id))
            if not cur.fetchone():
                print(f"接案紀錄 (u_id={u_id_taker}, r_id={r_id}) 不存在")
                return

            # 2. 檢查 request 是否屬於自己
            cur.execute("""
                SELECT u_id
                FROM user_request
                WHERE r_id = %s
            """, (r_id,))
            row = cur.fetchone()
            if not row:
                print(f"r_id={r_id} 在 user_request 不存在")
                return

            owner_in_db = row[0]
            if owner_in_db != u_id_owner:
                print(f"你不是該 request 的委託人，無法拒絕接案")
                return

            # 3. 刪除 take_request
            cur.execute("""
                DELETE FROM take_request
                WHERE u_id = %s AND r_id = %s
            """, (u_id_taker, r_id))

            conn.commit()
            print(f"成功拒絕接案: u_id={u_id_taker}, r_id={r_id}")

    except Exception as e:
        print("錯誤：", e)
        conn.rollback()
    finally:
        conn.close()

def my_course():
    u_id = input("輸入你的 u_id: ").strip()
    if not u_id.isdigit():
        print("u_id 必須為整數")
        return
    u_id = int(u_id)

    conn = get_connection()
    try:
        with conn.cursor() as cur:

            # ------------------你是 Teacher ------------------
            cur.execute("""
                SELECT 
                    c.c_id,
                    c.teacher_u_id,
                    c.student_u_id,
                    u.username,
                    u.realname,
                    u.email,
                    r.time,                     
                    r.target_gradeyear,
                    r.subject,
                    r.request_detail,
                    r.reward,    
                    r.place
                FROM course c
                JOIN "USER" u ON c.student_u_id = u.u_id
                JOIN user_request r ON r.r_id = c.r_id
                WHERE c.teacher_u_id = %s AND c.status = 'ongoing'
            """, (u_id,))
            rows_teacher = cur.fetchall()

            # ------------------你是 Student ------------------
            cur.execute("""
                SELECT 
                    c.c_id,
                    c.student_u_id,
                    c.teacher_u_id,
                    u.username,
                    u.realname,
                    u.email,
                    r.time,
                    r.target_gradeyear,
                    r.subject,
                    r.request_detail,
                    r.reward,
                    r.place
                FROM course c
                JOIN "USER" u ON c.teacher_u_id = u.u_id
                JOIN user_request r ON r.r_id = c.r_id
                WHERE c.student_u_id = %s AND c.status = 'ongoing'
            """, (u_id,))
            rows_student = cur.fetchall()

            # ------------------格式化 Teacher output------------------
            formatted_teacher = []
            for row in rows_teacher:
                (c_id, teacher_uid, student_uid,
                 username, realname, email,
                 take_time, grade_bits,
                 subject, detail, reward,place) = row

                # 處理 time (LEFT JOIN 可能得到 None)
                time_str = "No time"
                if take_time:
                    time_str = "\n".join(convert_168bit_to_ranges(take_time))

                grade_str = convert_grade_bits(grade_bits)

                formatted_teacher.append([
                    c_id,
                    teacher_uid,
                    student_uid,
                    username,
                    realname,
                    email,
                    time_str,
                    grade_str,
                    subject,
                    detail,
                    reward,
                    place
                ])

            headers_teacher = [
                "c_id", "teacher_u_id", "student_u_id",
                "username", "realname", "email",
                "time", "gradeyear",
                "subject", "request_detail","reward(per hour)", "place"
            ]

            # ------------------格式化 Student output------------------
            formatted_student = []
            for row in rows_student:
                (c_id, student_uid, teacher_uid,
                 username, realname, email,
                 take_time, grade_bits,
                 subject, detail, reward,place) = row

                time_str = "No time"
                if take_time:
                    time_str = "\n".join(convert_168bit_to_ranges(take_time))

                grade_str = convert_grade_bits(grade_bits)

                formatted_student.append([
                    c_id,
                    student_uid,
                    teacher_uid,
                    username,
                    realname,
                    email,
                    time_str,
                    grade_str,
                    subject,
                    detail,
                    reward,
                    place
                ])

            headers_student = [
                "c_id", "student_u_id", "teacher_u_id",
                "username", "realname", "email",
                "time", "gradeyear",
                "subject", "request_detail", "reward(per hour)","place"
            ]

            # ------------------輸出 Teacher ------------------
            print("\n===== 你是 Teacher 的 ongoing 課程 =====")
            if formatted_teacher:
                print(tabulate(formatted_teacher, headers=headers_teacher, tablefmt="psql"))
            else:
                print("沒有課程")

            # ------------------輸出 Student ------------------
            print("\n===== 你是 Student 的 ongoing 課程 =====")
            if formatted_student:
                print(tabulate(formatted_student, headers=headers_student, tablefmt="psql"))
            else:
                print("沒有課程")

    except Exception as e:
        print("錯誤：", e)
    finally:
        conn.close()

def rate_course():
    u_id = input("輸入你的 u_id: ").strip()
    c_id = input("輸入 c_id (COURSE): ").strip()
    score = input("輸入評分 (1~5): ").strip()

    # ---- 基本輸入檢查 ----
    if not (u_id.isdigit() and c_id.isdigit()):
        print("u_id 與 c_id 必須是整數")
        return

    try:
        score = float(score)
        if not (1 <= score <= 5):
            print("score 必須介於 1~5")
            return
    except ValueError:
        print("score 必須是數字")
        return

    u_id = int(u_id)
    c_id = int(c_id)

    conn = get_connection()
    try:
        with conn.cursor() as cur:

            # ---- 查詢該課程 ----
            cur.execute("""
                SELECT teacher_u_id, student_u_id
                FROM course
                WHERE c_id = %s
            """, (c_id,))
            row = cur.fetchone()

            if not row:
                print("查無此 c_id 的課程")
                return

            teacher_u_id, student_u_id = row

            # ---- 判斷使用者身份 ----
            if u_id == teacher_u_id:
                # Teacher 評 Student
                cur.execute("""
                    UPDATE course
                    SET student_score = %s
                    WHERE c_id = %s
                """, (score, c_id))
                conn.commit()
                print(f"成功！你已給 Student 評分：{score}")

            elif u_id == student_u_id:
                # Student 評 Teacher
                cur.execute("""
                    UPDATE course
                    SET teacher_score = %s
                    WHERE c_id = %s
                """, (score, c_id))
                conn.commit()
                print(f"成功！你已給 Teacher 評分：{score}")

            else:
                print("你沒有權限評分此課程")

    except Exception as e:
        print("發生錯誤：", e)
    finally:
        conn.close()

    #------------------ADMIN功能--------------------------
def admin_search_user():
    u_id = input("輸入要查詢的 u_id: ").strip()

    if not u_id.isdigit():
        print("u_id 必須為整數")
        return
    u_id = int(u_id)

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT u_id, username, realname, email, role, status
                FROM "USER"
                WHERE u_id = %s
            """, (u_id,))
            row = cur.fetchone()

            if not row:
                print("查無此使用者")
                return

            # 使用 tabulate 格式化輸出（如果你有使用 tabulate）
            headers = ["u_id", "username", "realname", "email", "role", "status"]
            print("\n===== 使用者資訊 =====")
            print(tabulate([row], headers=headers, tablefmt="psql"))

    except Exception as e:
        print("錯誤：", e)
    finally:
        conn.close()

def admin_edit_user_profile():
    u_id = input("輸入要修改密碼的 u_id: ").strip()
    new_password = input("輸入新的 password: ").strip()

    # ---- 基本輸入檢查 ----
    if not u_id.isdigit():
        print("u_id 必須為整數")
        return
    if not new_password:
        print("新密碼不能為空")
        return

    u_id = int(u_id)

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 確認使用者是否存在
            cur.execute("""
                SELECT u_id FROM "USER" WHERE u_id = %s
            """, (u_id,))
            row = cur.fetchone()

            if not row:
                print("查無此使用者")
                return

            # 更新密碼
            cur.execute("""
                UPDATE "USER"
                SET password = %s
                WHERE u_id = %s
            """, (new_password, u_id))
            conn.commit()

            print(f"成功！u_id = {u_id} 的密碼已更新為{new_password}。")

    except Exception as e:
        print("錯誤：", e)
    finally:
        conn.close()

def admin_suspended_user():
    admin_uid = input("輸入你的 u_id (ADMIN): ").strip()
    target_uid = input("輸入要停權的 u_id: ").strip()

    # ---- 基本輸入檢查 ----
    if not admin_uid.isdigit() or not target_uid.isdigit():
        print("所有 u_id 都必須為整數")
        return

    admin_uid = int(admin_uid)
    target_uid = int(target_uid)

    conn = get_connection()
    try:
        with conn.cursor() as cur:

            # ---- 檢查管理者是否存在 ----
            cur.execute("""
                SELECT u_id, role, status
                FROM "USER"
                WHERE u_id = %s
            """, (admin_uid,))
            admin_row = cur.fetchone()

            if not admin_row:
                print("你的 u_id 不存在，無法操作")
                return

            # ---- 查詢被停權者資訊 ----
            cur.execute("""
                SELECT u_id, role, status
                FROM "USER"
                WHERE u_id = %s
            """, (target_uid,))
            row = cur.fetchone()

            if not row:
                print("查無要停權的使用者")
                return

            _, role, status = row

            # ---- 檢查角色是否為 user ----
            if role != "user":
                print(f"無法停權！該使用者角色為 {role}（僅 role='user' 可停權）")
                return

            # ---- 停權並記錄 delete_by ----
            cur.execute("""
                UPDATE "USER"
                SET status = 'suspended', delete_by = %s
                WHERE u_id = %s
            """, (admin_uid, target_uid))
            conn.commit()

            print(f"成功！u_id = {target_uid} 已被停權，delete_by = {admin_uid}。")

    except Exception as e:
        print("錯誤：", e)
    finally:
        conn.close()


def admin_search_request():
    print("\n=== 查詢 user_request(可部分查詢) ===")
    r_id = input("輸入 r_id: ").strip()
    u_id = input("輸入 u_id: ").strip()

    # ---- 不能兩者都空 ----
    if not r_id and not u_id:
        print("錯誤：r_id 與 u_id 不可同時為空！")
        return

    # ---- 如果有輸入才檢查格式 ----
    if r_id and not r_id.isdigit():
        print("r_id 必須是整數")
        return
    if u_id and not u_id.isdigit():
        print("u_id 必須是整數")
        return

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # ---- 動態產生 where 條件 ----
            conditions = []
            params = []

            if r_id:
                conditions.append("r_id = %s")
                params.append(int(r_id))

            if u_id:
                conditions.append("u_id = %s")
                params.append(int(u_id))

            where_clause = " AND ".join(conditions)
            where_clause = "WHERE " + where_clause

            # ---- 查詢 ----
            cur.execute(f"""
                SELECT 
                    r_id,
                    u_id,
                    role,
                    target_gradeyear,
                    subject,
                    request_detail,
                    reward,
                    place,
                    time,
                    status
                FROM user_request
                {where_clause}
                ORDER BY r_id
            """, tuple(params))

            rows = cur.fetchall()

            if not rows:
                print("找不到符合條件的 request！")
                return

            # ---- 格式化輸出 ----
            formatted = []
            for row in rows:
                (r_id, u_id, role, grade_bits, subject,
                 detail, reward, place, time_bits, status) = row

                # ---- 轉換 time (168bits) ----
                if time_bits:
                    time_str = "\n".join(convert_168bit_to_ranges(time_bits))
                else:
                    time_str = "No time"

                # ---- 轉換年級 bits ----
                grade_str = convert_grade_bits(grade_bits)

                formatted.append([
                    r_id,
                    u_id,
                    role,
                    grade_str,
                    subject,
                    detail,
                    reward,
                    place,
                    time_str,
                    status
                ])

            headers = [
                "r_id", "u_id", "role(委託人)", "gradeyear",
                "subject", "request_detail", "reward",
                "place", "time", "status"
            ]

            print("\n===== 查詢結果 =====")
            print(tabulate(formatted, headers=headers, tablefmt="psql"))

    except Exception as e:
        print("錯誤：", e)

    finally:
        conn.close()

def admin_delete_request():
    print("\n=== 管理員刪除 user_request ===")

    admin_uid = input("輸入你的 u_id (ADMIN): ").strip()
    r_id = input("輸入要刪除的 r_id: ").strip()

    # ---- 基本輸入檢查 ----
    if not admin_uid.isdigit() or not r_id.isdigit():
        print("u_id 與 r_id 必須為整數")
        return

    admin_uid = int(admin_uid)
    r_id = int(r_id)

    conn = get_connection()
    try:
        with conn.cursor() as cur:

            # ---- 檢查管理者是否存在 ----
            cur.execute("""
                SELECT u_id, role, status
                FROM "USER"
                WHERE u_id = %s
            """, (admin_uid,))
            admin_row = cur.fetchone()

            if not admin_row:
                print("你的 u_id 不存在，無法操作")
                return

            # ---- 檢查 r_id 是否存在 ----
            cur.execute("""
                SELECT r_id, status
                FROM user_request
                WHERE r_id = %s
            """, (r_id,))
            req_row = cur.fetchone()

            if not req_row:
                print("查無此 r_id 的 request")
                return

            # ---- 更新 status 與 delete_by ----
            cur.execute("""
                UPDATE user_request
                SET status = 'deleted', delete_by = %s
                WHERE r_id = %s
            """, (admin_uid, r_id))
            conn.commit()

            print(f"成功！r_id = {r_id} 已被刪除，delete_by = {admin_uid}。")

    except Exception as e:
        print("錯誤：", e)

    finally:
        conn.close()

def admin_search_take_request():
    print("\n=== 查詢 take_request(可部分查詢) ===")
    r_id = input("輸入 r_id: ").strip()
    u_id = input("輸入接案人 u_id: ").strip()

    # ---- 不能兩者都空 ----
    if not r_id and not u_id:
        print("錯誤：r_id 與接案人 u_id 不可同時為空！")
        return

    # ---- 格式檢查 ----
    if r_id and not r_id.isdigit():
        print("r_id 必須是整數")
        return
    if u_id and not u_id.isdigit():
        print("接案人 u_id 必須是整數")
        return

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # ---- 動態組 where 條件 ----
            conditions = []
            params = []

            if r_id:
                conditions.append("r_id = %s")
                params.append(int(r_id))

            if u_id:
                conditions.append("u_id = %s")
                params.append(int(u_id))

            where_clause = " AND ".join(conditions)
            where_clause = "WHERE " + where_clause

            # ---- 查詢 ----
            cur.execute(f"""
                SELECT r_id, u_id, time
                FROM take_request
                {where_clause}
                ORDER BY r_id
            """, tuple(params))

            rows = cur.fetchall()

            if not rows:
                print("找不到符合條件的 take_request！")
                return

            # ---- 格式化輸出 ----
            formatted = []
            for row in rows:
                rid, taker_uid, time_bits = row

                # ---- time 轉換 ----
                if time_bits:
                    time_str = "\n".join(convert_168bit_to_ranges(time_bits))
                else:
                    time_str = "No time"

                formatted.append([rid, taker_uid, time_str])

            headers = ["r_id", "u_id(接案人)", "time"]

            print("\n===== 查詢結果 =====")
            print(tabulate(formatted, headers=headers, tablefmt="psql"))

    except Exception as e:
        print("錯誤：", e)

    finally:
        conn.close()

def admin_delete_take_request():
    print("\n=== 管理員刪除 take_request ===")

    r_id = input("輸入要刪除的 r_id: ").strip()
    u_id = input("輸入該request的接案人 u_id: ").strip()

    # ---- 基本檢查 ----
    if not r_id.isdigit() or not u_id.isdigit():
        print("r_id 與 u_id 必須為整數")
        return

    r_id = int(r_id)
    u_id = int(u_id)

    conn = get_connection()
    try:
        with conn.cursor() as cur:

            # ---- 檢查是否存在該筆 take_request ----
            cur.execute("""
                SELECT r_id
                FROM take_request
                WHERE r_id = %s AND u_id = %s
            """, (r_id, u_id))
            row = cur.fetchone()

            if not row:
                print("找不到符合條件的 take_request！")
                return

            # ---- 刪除紀錄 ----
            cur.execute("""
                DELETE FROM take_request
                WHERE r_id = %s AND u_id = %s
            """, (r_id, u_id))
            conn.commit()

            print(f"成功刪除 take_request：r_id = {r_id}, u_id = {u_id}。")

    except Exception as e:
        print("錯誤：", e)
    finally:
        conn.close()

def admin_search_course():
    print("\n=== 管理員查詢 course ===")
    c_id = input("輸入 c_id: ").strip()

    # ---- 檢查必填 ----
    if not c_id:
        print("錯誤：c_id 不可為空")
        return
    if not c_id.isdigit():
        print("c_id 必須是整數")
        return

    c_id = int(c_id)

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # ---- 查詢 ----
            cur.execute("""
                SELECT c_id, r_id, student_u_id, teacher_u_id, student_score, teacher_score, status
                FROM course
                WHERE c_id = %s
            """, (c_id,))

            row = cur.fetchone()

            if not row:
                print(f"找不到 c_id = {c_id} 的課程")
                return

            # ---- 格式化輸出 ----
            c_id_val, r_id_val, student_uid, teacher_uid, student_score, teacher_score, status = row
            formatted = [[c_id_val, r_id_val, student_uid, teacher_uid, student_score, teacher_score, status]]

            headers = ["c_id", "r_id", "student_u_id", "teacher_u_id", "student_score", "teacher_score", "status"]

            print("\n===== 查詢結果 =====")
            print(tabulate(formatted, headers=headers, tablefmt="psql"))

    except Exception as e:
        print("錯誤：", e)
    finally:
        conn.close()

def admin_delete_course():
    print("\n=== 管理員刪除 course ===")
    
    admin_uid = input("輸入你的 u_id (ADMIN): ").strip()
    c_id = input("輸入要刪除的 c_id: ").strip()

    # ---- 基本檢查 ----
    if not admin_uid.isdigit() or not c_id.isdigit():
        print("u_id 與 c_id 必須為整數")
        return

    admin_uid = int(admin_uid)
    c_id = int(c_id)

    conn = get_connection()
    try:
        with conn.cursor() as cur:

            # ---- 檢查管理員是否存在 ----
            cur.execute("""
                SELECT u_id, role, status
                FROM "USER"
                WHERE u_id = %s
            """, (admin_uid,))
            admin_row = cur.fetchone()
            if not admin_row:
                print("管理員 u_id 不存在")
                return

            # ---- 檢查課程是否存在 ----
            cur.execute("""
                SELECT c_id, status
                FROM course
                WHERE c_id = %s
            """, (c_id,))
            course_row = cur.fetchone()
            if not course_row:
                print(f"找不到 c_id = {c_id} 的課程")
                return

            # ---- 更新課程狀態與 delete_by ----
            cur.execute("""
                UPDATE course
                SET status = 'deleted', delete_by = %s
                WHERE c_id = %s
            """, (admin_uid, c_id))
            conn.commit()

            print(f"成功！c_id = {c_id} 的課程已被標記為 deleted，delete_by = {admin_uid}")

    except Exception as e:
        print("錯誤：", e)
    finally:
        conn.close()

def admin_reset_course_rate():
    print("\n=== 管理員重置課程評分 ===")
    
    c_id = input("輸入要重置評分的 c_id: ").strip()

    # ---- 基本檢查 ----
    if not c_id.isdigit():
        print("c_id 必須為整數")
        return

    c_id = int(c_id)

    conn = get_connection()
    try:
        with conn.cursor() as cur:

            # ---- 檢查課程是否存在 ----
            cur.execute("""
                SELECT c_id
                FROM course
                WHERE c_id = %s
            """, (c_id,))
            course_row = cur.fetchone()
            if not course_row:
                print(f"找不到 c_id = {c_id} 的課程")
                return

            # ---- 將評分設為 NULL ----
            cur.execute("""
                UPDATE course
                SET student_score = NULL,
                    teacher_score = NULL
                WHERE c_id = %s
            """, (c_id,))
            conn.commit()

            print(f"成功重置 c_id = {c_id} 的 student_score 與 teacher_score 為 NULL")

    except Exception as e:
        print("錯誤：", e)
    finally:
        conn.close()


# ------------------ CLI / Controller Layer ------------------
def main():
    actions = {
        #login/signin
        "1": ("sign_up", sign_up),
        "2": ("login", login),
        #user
        "3": ("edit_password",edit_password),
        "4": ("delete_profile",delete_account),
        "5": ("post_request",post_request),
        "6": ("my_request",my_request),
        "7": ("edit_request(未完成)",edit_request),
        "8": ("delete_request",delete_request),
        "9": ("search_request",search_request),
        "10": ("take_request",take_request),
        "11": ("my_take_request",my_take_request),
        "12": ("delete_take_request",delete_take_request),
        "13": ("my_request_taken_by",my_request_taken_by),
        "14": ("confirm_request_taken_by",confirm_request_taken_by),
        "15": ("deny_request_taken_by",deny_request_taken_by),
        "16": ("my_course",my_course),
        "17": ("rate_course",rate_course),
        #admin
        "18": ("admin_search_user",admin_search_user),
        "19": ("admin_edit_user_profile",admin_edit_user_profile),
        "20": ("admin_suspended_user",admin_suspended_user),
        "21": ("admin_search_request",admin_search_request),
        "22": ("admin_delete_request",admin_delete_request),
        "23": ("admin_search_take_request",admin_search_take_request),
        "24": ("admin_delete_take_request",admin_delete_take_request),
        "25": ("admin_search_course",admin_search_course),
        "26": ("admin_delete_course",admin_delete_course),
        "27": ("admin_reset_course_rate",admin_reset_course_rate)
    }

    while True:
        print("\n請選擇動作：")
        for key, (desc, _) in actions.items():
            print(f"{key}. {desc}")
        print("q. 離開")

        choice = input("輸入選項： ").strip()

        if choice == "q":
            print("程式結束")
            break
        elif choice in actions:
            _, action_func = actions[choice]
            action_func()
        else:
            print("無效選項，請重新輸入")

if __name__ == "__main__":
    main()
'''