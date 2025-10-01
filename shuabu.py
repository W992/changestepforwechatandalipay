# -*- coding: utf8 -*-
#change BY W992
#感谢大佬提供的新方式
#https://github.com/hanximeng/Zepp_API/blob/main/index.php
import math, re, os, json, random, time, traceback ,urllib
from datetime import datetime
import pytz
import requests
from Crypto.Cipher import AES

sleep_seconds = 5

# 账号获取方式1
users = os.environ.get('zepp_user', '')
#格式 账号1#账号2#...
passwords = os.environ.get('zeppp_assword', '')
#格式 密码1#密码2#...

# 账号获取方式2
# users = 'user1@qq.com#user2@qq.com#user3@qq.com#...'
# passwords = 'password1#password2#password3#...'

#步数设置
min_step = 88000
max_step = 93000

# 获取当前时间对应的最大和最小步数  按需修改 peak_time = 1 * 60  中的1 表示到1点就随机最大步数，即当1点后就是100%步数，
def get_min_max_by_time(min_step: int, max_step: int, hour=None, minute=None):
    if hour is None:
        hour = get_beijing_time().hour
    if minute is None:
        minute = get_beijing_time().minute
    time_progress = hour * 60 + minute
    peak_time = 1 * 60
    time_rate = min(time_progress / peak_time, 1.0)
    scaled_min = int(min_step * time_rate)
    scaled_max = int(max_step * time_rate)
    return scaled_min, scaled_max
    
fake_ip_num = 5
ip_list = ["42.123.64.0", "58.66.192.0", "61.138.192.0", "61.159.64.0", "114.66.0.0", "114.67.64.0", "114.113.64.0", "114.115.128.0", "116.63.64.0", "124.40.128.0", "124.203.192.0", "203.156.192.0"]
UserAgent_List = [
    "MiFit/5.5.1 (iPhone; CPU iPhone OS 14_3 like Mac OS X) ",
    "Dalvik/2.1.0 (Linux; Android 14; 2211133C Build/UKQ1.230804.001)"
]
# 获取北京时间
def get_beijing_time():
    target_timezone = pytz.timezone('Asia/Shanghai')
    # 获取当前时间
    return datetime.now().astimezone(target_timezone)

# 参考自 https://github.com/hanximeng/Zepp_API/blob/main/index.php
def encrypt_data(plain: bytes) -> bytes:
    key = b'xeNtBVqzDc6tuNTh'  # 16 bytes
    iv = b'MAAAYAAAAAAAAABg'  # 16 bytes
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # AES-128-CBC 使用 PKCS#7 填充。
    pad_len = AES.block_size - (len(plain) % AES.block_size)
    padded = plain + bytes([pad_len]) * pad_len
    return cipher.encrypt(padded)

# 格式化时间
def format_now():
    return get_beijing_time().strftime("%Y-%m-%d %H:%M:%S")

# 获取默认值转int
def get_int_value_default(_config: dict, _key, default):
    _config.setdefault(_key, default)
    return int(_config.get(_key))

# 获取当前时间对应的最大和最小步数
def get_min_max_by_time(min_step: int, max_step: int, hour=None, minute=None):
    if hour is None:
        hour = get_beijing_time().hour
    if minute is None:
        minute = get_beijing_time().minute
    time_progress = hour * 60 + minute
    peak_time = 1 * 60
    time_rate = min(time_progress / peak_time, 1.0)
    scaled_min = int(min_step * time_rate)
    scaled_max = int(max_step * time_rate)
    return scaled_min, scaled_max
# 获取时间戳
def get_time():
    current_time = get_beijing_time()
    return "%.0f" % (current_time.timestamp() * 1000)
# 虚拟ip地址
def fake_ip():
    target_ip = ip_list[fake_ip_num-1]
    one_num = int(target_ip.split('.')[0])
    two_num = int(target_ip.split('.')[1])
    third_num = int(target_ip.split('.')[2])
    if third_num == 0:
        return f"{one_num}.{two_num}.{random.randint(0, 63)}.{random.randint(1, 254)}"
    elif third_num == 64:
        return f"{one_num}.{two_num}.{random.randint(64, 127)}.{random.randint(1, 254)}"
    elif third_num == 128:
        return f"{one_num}.{two_num}.{random.randint(128, 191)}.{random.randint(1, 254)}"
    elif third_num == 192:
        return f"{one_num}.{two_num}.{random.randint(192, 255)}.{random.randint(1, 254)}"


# 账号脱敏
def desensitize_user_name(user):
    if len(user) <= 8:
        ln = max(math.floor(len(user) / 3), 1)
        return f'{user[:ln]}***{user[-ln:]}'
    return f'{user[:3]}****{user[-4:]}'

# 获取登录code
def get_access_token(location):
    code_pattern = re.compile("(?<=access=).*?(?=&)")
    result = code_pattern.findall(location)
    if result is None or len(result) == 0:
        return None
    return result[0]

class MiMotionRunner:
    def __init__(self, _user, _passwd):
        user = str(_user)
        password = str(_passwd)
        self.invalid = False
        self.log_str = ""
        if user == '' or password == '':
            self.error = "用户名或密码填写有误！"
            self.invalid = True
        self.password = password
        if "+86" in user or "@" in user:
            user = user  # 已经是手机号/邮箱
        else:
            user = "+86" + user  # 默认补全 +86
        if "+86" in user:
            self.is_phone = True
        else:
            self.is_phone = False
        self.user = user
        self.fake_ip_addr = fake_ip()  # 获取虚拟IP
        self.log_str += f"创建虚拟ip地址：{self.fake_ip_addr}\n"


    # ========== 缓存登录凭据的方法 ==========
    def _cache_login_credentials(self, login_token, userid):
        # 缓存 login_token
        cache_dir_login = "logintokens"
        cache_file_login = f"{cache_dir_login}/{self.user}.txt"
        os.makedirs(cache_dir_login, exist_ok=True)
        try:
            with open(cache_file_login, 'w', encoding='utf-8') as f:
                f.write(login_token)
            self.log_str += f"✅ 已缓存 login_token \n"
        except Exception as e:
            self.log_str += f"❌ 缓存 login_token 失败: {str(e)}\n"

        # 缓存 userid
        cache_dir_userid = "userids"
        cache_file_userid = f"{cache_dir_userid}/{self.user}.txt"
        os.makedirs(cache_dir_userid, exist_ok=True)
        try:
            with open(cache_file_userid, 'w', encoding='utf-8') as f:
                f.write(userid)
            self.log_str += f"✅ 已缓存 userid \n"
        except Exception as e:
            self.log_str += f"❌ 缓存 userid 失败: {str(e)}\n"

    def login(self):
        today_weekday = datetime.today().weekday()
        if today_weekday == 0:
            self.log_str += f"📅 今天是周一（{datetime.today()}），强制获取新 code，不使用任何缓存！\n"
            return self._get_fresh_code_flow()

        return self._regular_login_flow()

    def _regular_login_flow(self):
        cache_dir_login = "logintokens"
        cache_file_login = f"{cache_dir_login}/{self.user}.txt"
        os.makedirs(cache_dir_login, exist_ok=True)

        def try_cached_login_token():
            if os.path.exists(cache_file_login):
                try:
                    with open(cache_file_login, 'r', encoding='utf-8') as f:
                        cached_login_token = f.read().strip()
                    self.log_str += f"🔍 发现缓存的 login_token，尝试验证其有效性...\n"
                    app_token = self.get_app_token(cached_login_token)
                    if app_token:
                        self.log_str += f"✅ login_token 有效\n"

                        # 尝试读取缓存的 userid
                        cache_dir_userid = "userids"
                        cache_file_userid = f"{cache_dir_userid}/{self.user}.txt"
                        userid = None
                        if os.path.exists(cache_file_userid):
                            try:
                                with open(cache_file_userid, 'r', encoding='utf-8') as f:
                                    userid = f.read().strip()
                                # self.log_str += f"✅ 同时 userid，直接使用\n"
                            except Exception as e:
                                self.log_str += f"⚠️ 读取缓存的 userid 失败: {str(e)}\n"

                        if userid:
                            return cached_login_token, userid
                        else:
                            self.log_str += f"⚠️ 未找到缓存的 userid，但 login_token 有效\n"
                            return cached_login_token, None
                    else:
                        self.log_str += f"❌ 缓存的 login_token 无效，将重新获取\n"
                except Exception as e:
                    self.log_str += f"❌ 读取或验证缓存的 login_token 出错: {str(e)}\n"

            return None

        cached_result = try_cached_login_token()
        # self.log_str += f"{cached_result}\n"

        if cached_result:
            cached_login_token, cached_userid = cached_result
            if cached_userid:
                return cached_login_token, cached_userid

        # ---- 先查 code 缓存 ----
        return self._cached_code_flow()

    # ---------- 尝试通过缓存 code 换取 login_token ----------
    def _cached_code_flow(self):
        cache_dir_code = "code"
        cache_file_code = f"{cache_dir_code}/{self.user}.txt"
        os.makedirs(cache_dir_code, exist_ok=True)

        def _get_valid_code_and_login():
            if os.path.exists(cache_file_code):
                try:
                    with open(cache_file_code, 'r', encoding='utf-8') as f:
                        cached_code = f.read().strip()
                    self.log_str += f"🔍 发现缓存的 code，尝试通过它获取 login_token 和 userid...\n"
                    try:
                        login_token, userid = self._get_login_token(cached_code)
                        self.log_str += f"✅ 通过缓存的 code 成功获取到 login_token 和 userid\n"
                        self._cache_login_credentials(login_token, userid)
                        return login_token, userid
                    except Exception as e:
                        self.log_str += f"❌ 通过缓存的 code 获取 login_token 和 userid 失败: {str(e)}\n"
                except Exception as e:
                    self.log_str += f"❌ 读取缓存 code 文件失败: {str(e)}\n"
            return None

        def _fetch_new_code():
            nonlocal headers
            login_data = {
                'emailOrPhone': self.user,
                'password': self.password,
                'state': 'REDIRECTION',
                'client_id': 'HuaMi',
                'country_code': 'CN',
                'token': 'access',
                'redirect_uri': 'https://s3-us-west-2.amazonaws.com/hm-registration/successsignin.html',
            }
            query = urllib.parse.urlencode(login_data)
            plaintext = query.encode('utf-8')
            cipher_data = encrypt_data(plaintext)

            url1 = 'https://api-user.zepp.com/v2/registrations/tokens'
            r1 = requests.post(url1, data=cipher_data, headers=headers, allow_redirects=False)
            location = r1.headers.get("Location")

            try:
                code = get_access_token(location)
                if not code:
                    self.log_str += "❌ 从 Location 中解析 accessToken 失败\n"
                    return None
            except Exception as e:
                self.log_str += f"❌ 获取 accessToken 异常: {traceback.format_exc()}\n"
                return None

            try:
                with open(cache_file_code, 'w', encoding='utf-8') as f:
                    f.write(code)
                self.log_str += f"✅ 保存新 code 成功\n"
            except Exception as e:
                self.log_str += f"❌ 保存新 code 失败: {str(e)}\n"

            return code

        def _get_login_token(code):
            headers = {
                "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                "user-agent": useragent,
                "app_name": "com.xiaomi.hm.health",
                "appplatform": "android_phone",
                "x-hm-ekv": "1",
                "hm-privacy-ceip": "false",
                "X-Forwarded-For": self.fake_ip_addr
            }
            url2 = "https://account.huami.com/v2/client/login"
            data2 = {
                "app_name": "com.xiaomi.hm.health",
                "app_version": "6.3.5" if not self.is_phone else "4.6.0",
                "code": code,
                "country_code": "CN",
                "device_id": "2C8B4939-0CCD-4E94-8CBA-CB8EA6E613A1",
                "device_model": "phone",
                "grant_type": "access_token",
                "third_name": "huami_phone" if self.is_phone else "email",
                **({"dn": "api-user.huami.com%2Capi-mifit.huami.com%2Capp-analytics.huami.com", 
                "lang": "zh_CN", "os_version": "1.5.0", "source": "com.xiaomi.hm.health", 
                "allow_registration=": "false"} if not self.is_phone else {})
            }
            r2 = requests.post(url2, data=data2, headers=headers).json()
            login_token = r2.get("token_info", {}).get("login_token")
            userid = r2.get("token_info", {}).get("user_id")
            if not login_token or not userid:
                raise ValueError("登录失败：未能从响应中获取 login_token 或 user_id")
            return login_token, userid

        headers = {
            "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
            "user-agent": useragent,
            "app_name": "com.xiaomi.hm.health",
            "appplatform": "android_phone",
            "x-hm-ekv": "1",
            "hm-privacy-ceip": "false",
            "X-Forwarded-For": self.fake_ip_addr
        }

        result = _get_valid_code_and_login()
        if result:
            return result

        code = _fetch_new_code()
        if not code:
            self.log_str += "❌ 无法获取新的 code\n"
            return 0, 0

        try:
            login_token, userid = _get_login_token(code)
        except Exception as e:
            self.log_str += f"❌ 使用新 code 获取 login_token 失败: {str(e)}\n"
            return 0, 0

        # 缓存 login_token 和 userid
        self._cache_login_credentials(login_token, userid)

        return login_token, userid

    # ----------强制获取新 code----------
    def _get_fresh_code_flow(self):
        cache_dir_code = "code"
        cache_file_code = f"{cache_dir_code}/{self.user}.txt"
        os.makedirs(cache_dir_code, exist_ok=True)

        cache_dir_login = "logintokens"
        cache_file_login = f"{cache_dir_login}/{self.user}.txt"
        os.makedirs(cache_dir_login, exist_ok=True)

        cache_dir_userid = "userids"
        cache_file_userid = f"{cache_dir_userid}/{self.user}.txt"
        os.makedirs(cache_dir_userid, exist_ok=True)

        headers = {
            "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
            "user-agent": useragent,
            "app_name": "com.xiaomi.hm.health",
            "appplatform": "android_phone",
            "x-hm-ekv": "1",
            "hm-privacy-ceip": "false",
            "X-Forwarded-For": self.fake_ip_addr
        }

        # 1. 获取新 code
        login_data = {
            'emailOrPhone': self.user,
            'password': self.password,
            'state': 'REDIRECTION',
            'client_id': 'HuaMi',
            'country_code': 'CN',
            'token': 'access',
            'redirect_uri': 'https://s3-us-west-2.amazonaws.com/hm-registration/successsignin.html',
        }
        query = urllib.parse.urlencode(login_data)
        plaintext = query.encode('utf-8')
        cipher_data = encrypt_data(plaintext)

        url1 = 'https://api-user.zepp.com/v2/registrations/tokens'
        r1 = requests.post(url1, data=cipher_data, headers=headers, allow_redirects=False)
        location = r1.headers.get("Location")
        if not location:
            self.log_str += "❌ 响应中没有 Location，无法提取 code\n"
            return 0, 0

        try:
            code = get_access_token(location)
            if not code:
                self.log_str += "❌ 从 Location 中解析 accessToken 失败\n"
                return 0, 0
        except Exception as e:
            self.log_str += f"❌ 获取 accessToken 异常: {traceback.format_exc()}\n"
            return 0, 0

        try:
            with open(cache_file_code, 'w', encoding='utf-8') as f:
                f.write(code)
            self.log_str += f"✅ 【周一】保存新 code 成功\n"
        except Exception as e:
            self.log_str += f"❌ 保存新 code 失败: {str(e)}\n"

        # 2. 用新 code 换取 login_token 和 userid
        url2 = "https://account.huami.com/v2/client/login"
        data2 = {
            "app_name": "com.xiaomi.hm.health",
            "app_version": "6.3.5" if not self.is_phone else "4.6.0",
            "code": code,
            "country_code": "CN",
            "device_id": "2C8B4939-0CCD-4E94-8CBA-CB8EA6E613A1",
            "device_model": "phone",
            "grant_type": "access_token",
            "third_name": "huami_phone" if self.is_phone else "email",
            **({"dn": "api-user.huami.com%2Capi-mifit.huami.com%2Capp-analytics.huami.com", 
            "lang": "zh_CN", "os_version": "1.5.0", "source": "com.xiaomi.hm.health", 
            "allow_registration=": "false"} if not self.is_phone else {})
        }
        r2 = requests.post(url2, data=data2, headers=headers).json()
        login_token = r2.get("token_info", {}).get("login_token")
        userid = r2.get("token_info", {}).get("user_id")
        if not login_token or not userid:
            self.log_str += "❌ 【周一】登录失败：未能从响应中获取 login_token 或 user_id\n"
            return 0, 0

        # 3. 缓存 login_token 和 userid
        try:
            with open(cache_file_login, 'w', encoding='utf-8') as f:
                f.write(login_token)
            self.log_str += f"✅ 【周一】已缓存 login_token: {login_token[:10]}...\n"
        except Exception as e:
            self.log_str += f"❌ 缓存 login_token 失败: {str(e)}\n"

        try:
            with open(cache_file_userid, 'w', encoding='utf-8') as f:
                f.write(userid)
            self.log_str += f"✅ 【周一】已缓存 userid: {userid}\n"
        except Exception as e:
            self.log_str += f"❌ 缓存 userid 失败: {str(e)}\n"

        return login_token, userid

    # ========== 获取 app_token==========
    def get_app_token(self, login_token):
        url = f"https://account-cn.huami.com/v1/client/app_tokens?app_name=com.xiaomi.hm.health&dn=api-user.huami.com%2Capi-mifit.huami.com%2Capp-analytics.huami.com&login_token={login_token}"
        headers = {'User-Agent': 'MiFit/5.3.0 (iPhone; iOS 14.7.1; Scale/3.00)', 'X-Forwarded-For': self.fake_ip_addr}
        response = requests.get(url, headers=headers).json()
        if not response or 'token_info' not in response or 'app_token' not in response['token_info']:
            self.log_str += "❌ 获取 app_token 失败，返回数据异常或 login_token 可能失效\n"
            return None
        app_token = response['token_info']['app_token']
        self.log_str += f"✅ 获取 app_token：{app_token[:10]}...\n"
        return app_token

    def login_and_post_step(self, min_step, max_step):
        if self.invalid:
            return "账号或密码配置有误", False
        step = str(random.randint(min_step, max_step))
        self.log_str += f"✅ 已设置随机步数范围({min_step}~{max_step})，值为: {step}\n"

        login_token, userid = self.login()
        if login_token == 0:
            return "登录失败！", False

        t = get_time()  

        app_token = self.get_app_token(login_token)
        if not app_token:
            return "获取 app_token 失败！", False

        today = time.strftime("%F") 

        data_json = '%5B%7B%22data_hr%22%3A%22%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F9L%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2FVv%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F0v%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F9e%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F0n%5C%2Fa%5C%2F%5C%2F%5C%2FS%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F0b%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F1FK%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2FR%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F9PTFFpaf9L%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2FR%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F0j%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F9K%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2FOv%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2Fzf%5C%2F%5C%2F%5C%2F86%5C%2Fzr%5C%2FOv88%5C%2Fzf%5C%2FPf%5C%2F%5C%2F%5C%2F0v%5C%2FS%5C%2F8%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2FSf%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2Fz3%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F0r%5C%2FOv%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2FS%5C%2F9L%5C%2Fzb%5C%2FSf9K%5C%2F0v%5C%2FRf9H%5C%2Fzj%5C%2FSf9K%5C%2F0%5C%2F%5C%2FN%5C%2F%5C%2F%5C%2F%5C%2F0D%5C%2FSf83%5C%2Fzr%5C%2FPf9M%5C%2F0v%5C%2FOv9e%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2FS%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2Fzv%5C%2F%5C%2Fz7%5C%2FO%5C%2F83%5C%2Fzv%5C%2FN%5C%2F83%5C%2Fzr%5C%2FN%5C%2F86%5C%2Fz%5C%2F%5C%2FNv83%5C%2Fzn%5C%2FXv84%5C%2Fzr%5C%2FPP84%5C%2Fzj%5C%2FN%5C%2F9e%5C%2Fzr%5C%2FN%5C%2F89%5C%2F03%5C%2FP%5C%2F89%5C%2Fz3%5C%2FQ%5C%2F9N%5C%2F0v%5C%2FTv9C%5C%2F0H%5C%2FOf9D%5C%2Fzz%5C%2FOf88%5C%2Fz%5C%2F%5C%2FPP9A%5C%2Fzr%5C%2FN%5C%2F86%5C%2Fzz%5C%2FNv87%5C%2F0D%5C%2FOv84%5C%2F0v%5C%2FO%5C%2F84%5C%2Fzf%5C%2FMP83%5C%2FzH%5C%2FNv83%5C%2Fzf%5C%2FN%5C%2F84%5C%2Fzf%5C%2FOf82%5C%2Fzf%5C%2FOP83%5C%2Fzb%5C%2FMv81%5C%2FzX%5C%2FR%5C%2F9L%5C%2F0v%5C%2FO%5C%2F9I%5C%2F0T%5C%2FS%5C%2F9A%5C%2Fzn%5C%2FPf89%5C%2Fzn%5C%2FNf9K%5C%2F07%5C%2FN%5C%2F83%5C%2Fzn%5C%2FNv83%5C%2Fzv%5C%2FO%5C%2F9A%5C%2F0H%5C%2FOf8%5C%2F%5C%2Fzj%5C%2FPP83%5C%2Fzj%5C%2FS%5C%2F87%5C%2Fzj%5C%2FNv84%5C%2Fzf%5C%2FOf83%5C%2Fzf%5C%2FOf83%5C%2Fzb%5C%2FNv9L%5C%2Fzj%5C%2FNv82%5C%2Fzb%5C%2FN%5C%2F85%5C%2Fzf%5C%2FN%5C%2F9J%5C%2Fzf%5C%2FNv83%5C%2Fzj%5C%2FNv84%5C%2F0r%5C%2FSv83%5C%2Fzf%5C%2FMP%5C%2F%5C%2F%5C%2Fzb%5C%2FMv82%5C%2Fzb%5C%2FOf85%5C%2Fz7%5C%2FNv8%5C%2F%5C%2F0r%5C%2FS%5C%2F85%5C%2F0H%5C%2FQP9B%5C%2F0D%5C%2FNf89%5C%2Fzj%5C%2FOv83%5C%2Fzv%5C%2FNv8%5C%2F%5C%2F0f%5C%2FSv9O%5C%2F0ZeXv%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F1X%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F9B%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2FTP%5C%2F%5C%2F%5C%2F1b%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F0%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F9N%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%22%2C%22date%22%3A%222021-08-07%22%2C%22data%22%3A%5B%7B%22start%22%3A0%2C%22stop%22%3A1439%2C%22value%22%3A%22UA8AUBQAUAwAUBoAUAEAYCcAUBkAUB4AUBgAUCAAUAEAUBkAUAwAYAsAYB8AYB0AYBgAYCoAYBgAYB4AUCcAUBsAUB8AUBwAUBIAYBkAYB8AUBoAUBMAUCEAUCIAYBYAUBwAUCAAUBgAUCAAUBcAYBsAYCUAATIPYD0KECQAYDMAYB0AYAsAYCAAYDwAYCIAYB0AYBcAYCQAYB0AYBAAYCMAYAoAYCIAYCEAYCYAYBsAYBUAYAYAYCIAYCMAUB0AUCAAUBYAUCoAUBEAUC8AUB0AUBYAUDMAUDoAUBkAUC0AUBQAUBwAUA0AUBsAUAoAUCEAUBYAUAwAUB4AUAwAUCcAUCYAUCwKYDUAAUUlEC8IYEMAYEgAYDoAYBAAUAMAUBkAWgAAWgAAWgAAWgAAWgAAUAgAWgAAUBAAUAQAUA4AUA8AUAkAUAIAUAYAUAcAUAIAWgAAUAQAUAkAUAEAUBkAUCUAWgAAUAYAUBEAWgAAUBYAWgAAUAYAWgAAWgAAWgAAWgAAUBcAUAcAWgAAUBUAUAoAUAIAWgAAUAQAUAYAUCgAWgAAUAgAWgAAWgAAUAwAWwAAXCMAUBQAWwAAUAIAWgAAWgAAWgAAWgAAWgAAWgAAWgAAWgAAWREAWQIAUAMAWSEAUDoAUDIAUB8AUCEAUC4AXB4AUA4AWgAAUBIAUA8AUBAAUCUAUCIAUAMAUAEAUAsAUAMAUCwAUBYAWgAAWgAAWgAAWgAAWgAAWgAAUAYAWgAAWgAAWgAAUAYAWwAAWgAAUAYAXAQAUAMAUBsAUBcAUCAAWwAAWgAAWgAAWgAAWgAAUBgAUB4AWgAAUAcAUAwAWQIAWQkAUAEAUAIAWgAAUAoAWgAAUAYAUB0AWgAAWgAAUAkAWgAAWSwAUBIAWgAAUC4AWSYAWgAAUAYAUAoAUAkAUAIAUAcAWgAAUAEAUBEAUBgAUBcAWRYAUA0AWSgAUB4AUDQAUBoAXA4AUA8AUBwAUA8AUA4AUA4AWgAAUAIAUCMAWgAAUCwAUBgAUAYAUAAAUAAAUAAAUAAAUAAAUAAAUAAAUAAAUAAAWwAAUAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAeSEAeQ8AcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcBcAcAAAcAAAcCYOcBUAUAAAUAAAUAAAUAAAUAUAUAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcCgAeQAAcAAAcAAAcAAAcAAAcAAAcAYAcAAAcBgAeQAAcAAAcAAAegAAegAAcAAAcAcAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcCkAeQAAcAcAcAAAcAAAcAwAcAAAcAAAcAIAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcCIAeQAAcAAAcAAAcAAAcAAAcAAAeRwAeQAAWgAAUAAAUAAAUAAAUAAAUAAAcAAAcAAAcBoAeScAeQAAegAAcBkAeQAAUAAAUAAAUAAAUAAAUAAAUAAAcAAAcAAAcAAAcAAAcAAAcAAAegAAegAAcAAAcAAAcBgAeQAAcAAAcAAAcAAAcAAAcAAAcAkAegAAegAAcAcAcAAAcAcAcAAAcAAAcAAAcAAAcA8AeQAAcAAAcAAAeRQAcAwAUAAAUAAAUAAAUAAAUAAAUAAAcAAAcBEAcA0AcAAAWQsAUAAAUAAAUAAAUAAAUAAAcAAAcAoAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAYAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcBYAegAAcAAAcAAAegAAcAcAcAAAcAAAcAAAcAAAcAAAeRkAegAAegAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAEAcAAAcAAAcAAAcAUAcAQAcAAAcBIAeQAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcBsAcAAAcAAAcBcAeQAAUAAAUAAAUAAAUAAAUAAAUBQAcBYAUAAAUAAAUAoAWRYAWTQAWQAAUAAAUAAAUAAAcAAAcAAAcAAAcAAAcAAAcAMAcAAAcAQAcAAAcAAAcAAAcDMAeSIAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcBQAeQwAcAAAcAAAcAAAcAMAcAAAeSoAcA8AcDMAcAYAeQoAcAwAcFQAcEMAeVIAaTYAbBcNYAsAYBIAYAIAYAIAYBUAYCwAYBMAYDYAYCkAYDcAUCoAUCcAUAUAUBAAWgAAYBoAYBcAYCgAUAMAUAYAUBYAUA4AUBgAUAgAUAgAUAsAUAsAUA4AUAMAUAYAUAQAUBIAASsSUDAAUDAAUBAAYAYAUBAAUAUAUCAAUBoAUCAAUBAAUAoAYAIAUAQAUAgAUCcAUAsAUCIAUCUAUAoAUA4AUB8AUBkAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAA%22%2C%22tz%22%3A32%2C%22did%22%3A%22DA932FFFFE8816E7%22%2C%22src%22%3A24%7D%5D%2C%22summary%22%3A%22%7B%5C%22v%5C%22%3A6%2C%5C%22slp%5C%22%3A%7B%5C%22st%5C%22%3A1628296479%2C%5C%22ed%5C%22%3A1628296479%2C%5C%22dp%5C%22%3A0%2C%5C%22lt%5C%22%3A0%2C%5C%22wk%5C%22%3A0%2C%5C%22usrSt%5C%22%3A-1440%2C%5C%22usrEd%5C%22%3A-1440%2C%5C%22wc%5C%22%3A0%2C%5C%22is%5C%22%3A0%2C%5C%22lb%5C%22%3A0%2C%5C%22to%5C%22%3A0%2C%5C%22dt%5C%22%3A0%2C%5C%22rhr%5C%22%3A0%2C%5C%22ss%5C%22%3A0%7D%2C%5C%22stp%5C%22%3A%7B%5C%22ttl%5C%22%3A18272%2C%5C%22dis%5C%22%3A10627%2C%5C%22cal%5C%22%3A510%2C%5C%22wk%5C%22%3A41%2C%5C%22rn%5C%22%3A50%2C%5C%22runDist%5C%22%3A7654%2C%5C%22runCal%5C%22%3A397%2C%5C%22stage%5C%22%3A%5B%7B%5C%22start%5C%22%3A327%2C%5C%22stop%5C%22%3A341%2C%5C%22mode%5C%22%3A1%2C%5C%22dis%5C%22%3A481%2C%5C%22cal%5C%22%3A13%2C%5C%22step%5C%22%3A680%7D%2C%7B%5C%22start%5C%22%3A342%2C%5C%22stop%5C%22%3A367%2C%5C%22mode%5C%22%3A3%2C%5C%22dis%5C%22%3A2295%2C%5C%22cal%5C%22%3A95%2C%5C%22step%5C%22%3A2874%7D%2C%7B%5C%22start%5C%22%3A368%2C%5C%22stop%5C%22%3A377%2C%5C%22mode%5C%22%3A4%2C%5C%22dis%5C%22%3A1592%2C%5C%22cal%5C%22%3A88%2C%5C%22step%5C%22%3A1664%7D%2C%7B%5C%22start%5C%22%3A378%2C%5C%22stop%5C%22%3A386%2C%5C%22mode%5C%22%3A3%2C%5C%22dis%5C%22%3A1072%2C%5C%22cal%5C%22%3A51%2C%5C%22step%5C%22%3A1245%7D%2C%7B%5C%22start%5C%22%3A387%2C%5C%22stop%5C%22%3A393%2C%5C%22mode%5C%22%3A4%2C%5C%22dis%5C%22%3A1036%2C%5C%22cal%5C%22%3A57%2C%5C%22step%5C%22%3A1124%7D%2C%7B%5C%22start%5C%22%3A394%2C%5C%22stop%5C%22%3A398%2C%5C%22mode%5C%22%3A3%2C%5C%22dis%5C%22%3A488%2C%5C%22cal%5C%22%3A19%2C%5C%22step%5C%22%3A607%7D%2C%7B%5C%22start%5C%22%3A399%2C%5C%22stop%5C%22%3A414%2C%5C%22mode%5C%22%3A4%2C%5C%22dis%5C%22%3A2220%2C%5C%22cal%5C%22%3A120%2C%5C%22step%5C%22%3A2371%7D%2C%7B%5C%22start%5C%22%3A415%2C%5C%22stop%5C%22%3A427%2C%5C%22mode%5C%22%3A3%2C%5C%22dis%5C%22%3A1268%2C%5C%22cal%5C%22%3A59%2C%5C%22step%5C%22%3A1489%7D%2C%7B%5C%22start%5C%22%3A428%2C%5C%22stop%5C%22%3A433%2C%5C%22mode%5C%22%3A1%2C%5C%22dis%5C%22%3A152%2C%5C%22cal%5C%22%3A4%2C%5C%22step%5C%22%3A238%7D%2C%7B%5C%22start%5C%22%3A434%2C%5C%22stop%5C%22%3A444%2C%5C%22mode%5C%22%3A3%2C%5C%22dis%5C%22%3A2295%2C%5C%22cal%5C%22%3A95%2C%5C%22step%5C%22%3A2874%7D%2C%7B%5C%22start%5C%22%3A445%2C%5C%22stop%5C%22%3A455%2C%5C%22mode%5C%22%3A4%2C%5C%22dis%5C%22%3A1592%2C%5C%22cal%5C%22%3A88%2C%5C%22step%5C%22%3A1664%7D%2C%7B%5C%22start%5C%22%3A456%2C%5C%22stop%5C%22%3A466%2C%5C%22mode%5C%22%3A3%2C%5C%22dis%5C%22%3A1072%2C%5C%22cal%5C%22%3A51%2C%5C%22step%5C%22%3A1245%7D%2C%7B%5C%22start%5C%22%3A467%2C%5C%22stop%5C%22%3A477%2C%5C%22mode%5C%22%3A4%2C%5C%22dis%5C%22%3A1036%2C%5C%22cal%5C%22%3A57%2C%5C%22step%5C%22%3A1124%7D%2C%7B%5C%22start%5C%22%3A478%2C%5C%22stop%5C%22%3A488%2C%5C%22mode%5C%22%3A3%2C%5C%22dis%5C%22%3A488%2C%5C%22cal%5C%22%3A19%2C%5C%22step%5C%22%3A607%7D%2C%7B%5C%22start%5C%22%3A489%2C%5C%22stop%5C%22%3A499%2C%5C%22mode%5C%22%3A4%2C%5C%22dis%5C%22%3A2220%2C%5C%22cal%5C%22%3A120%2C%5C%22step%5C%22%3A2371%7D%2C%7B%5C%22start%5C%22%3A500%2C%5C%22stop%5C%22%3A511%2C%5C%22mode%5C%22%3A3%2C%5C%22dis%5C%22%3A1268%2C%5C%22cal%5C%22%3A59%2C%5C%22step%5C%22%3A1489%7D%2C%7B%5C%22start%5C%22%3A512%2C%5C%22stop%5C%22%3A522%2C%5C%22mode%5C%22%3A1%2C%5C%22dis%5C%22%3A152%2C%5C%22cal%5C%22%3A4%2C%5C%22step%5C%22%3A238%7D%5D%7D%2C%5C%22goal%5C%22%3A8000%2C%5C%22tz%5C%22%3A%5C%2228800%5C%22%7D%22%2C%22source%22%3A24%2C%22type%22%3A0%7D%5D'
         

        finddate = re.compile(r".*?date%22%3A%22(.*?)%22%2C%22data.*?")
        findstep = re.compile(r".*?ttl%5C%22%3A(.*?)%2C%5C%22dis.*?")
        if finddate.findall(data_json) and findstep.findall(data_json):
            data_json = re.sub(finddate.findall(data_json)[0], today, str(data_json))
            data_json = re.sub(findstep.findall(data_json)[0], step, str(data_json))
        else:
            pass

        url = f'https://api-mifit-cn.huami.com/v1/data/band_data.json?&t={t}'
        head = {
            "apptoken": app_token,
            "User-Agent": useragent,
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Forwarded-For": self.fake_ip_addr
        }

        data = f'userid={userid}&last_sync_data_time=1597306380&device_type=0&last_deviceid=DA932FFFFE8816E7&data_json={data_json}'

        try:
            response = requests.post(url, data=data, headers=head).json()
        except Exception as e:
            self.log_str += f"❌ 提交步数请求异常: {str(e)}\n"
            return f"提交步数失败：请求异常", False

        if not isinstance(response, dict):
            self.log_str += "❌ 提交步数：服务器返回的不是合法的 JSON\n"
            return f"提交步数失败：返回数据异常", False

        msg = response.get('message', '').lower()
        if msg == 'success':
            return f"修改步数（{step}）成功", True
        else:
            error_msg = response.get('message', '未知错误或服务端拒绝')
            self.log_str += f"❌ 提交步数失败！错误信息: {error_msg}\n"
            return f"修改步数（{step}）失败: {error_msg}", False
def run_single_account(total, idx, user_mi, passwd_mi,scaled_min_step, scaled_max_step):
    idx_info = ""
    if idx is not None:
        idx_info = f"[{idx + 1}/{total}]"
    log_str = f"[{format_now()}]\n{idx_info}账号：{desensitize_user_name(user_mi)}"
    try:
        runner = MiMotionRunner(user_mi, passwd_mi)
        exec_msg, success = runner.login_and_post_step(scaled_min_step, scaled_max_step)
        log_str += runner.log_str
        log_str += f'{exec_msg}\n'
        exec_result = {"user": user_mi, "success": success,
                       "msg": exec_msg}
    except:
        log_str += f"执行异常:{traceback.format_exc()}\n"
        log_str += traceback.format_exc()
        exec_result = {"user": user_mi, "success": False,
                       "msg": f"执行异常:{traceback.format_exc()}"}
    print(log_str)
    return exec_result


def execute():
    user_list = users.split('#')
    passwd_list = passwords.split('#')

    total = len(user_list)
    if len(user_list) != len(passwd_list):
        print(f"❌ 错误：用户数量({len(user_list)}) 与 密码数量({len(passwd_list)}) 不匹配！")
        exit(1)

    exec_results = []
    for idx in range(total):
        user_mi = user_list[idx]
        passwd_mi = passwd_list[idx]

        ua_index = idx % len(UserAgent_List)
        global useragent
        useragent = UserAgent_List[ua_index]

        scaled_min_step, scaled_max_step = get_min_max_by_time(min_step, max_step)

        exec_results.append(
            run_single_account(total, idx, user_mi, passwd_mi, scaled_min_step, scaled_max_step)
        )

        if idx < total - 1:
            time.sleep(sleep_seconds)

    success_count = sum(1 for r in exec_results if r.get('success', False))
    print(f"\n✅ 执行完毕：总账号数 {total}，成功 {success_count}，失败 {total - success_count}")



if __name__ == "__main__":
    if sleep_seconds is None or sleep_seconds == '':
        sleep_seconds = 5
    sleep_seconds = float(sleep_seconds)
    users = users
    passwords = passwords
    if users is None or passwords is None:
        print("未正确配置账号密码，无法执行")
        exit(1)
    use_concurrent = "False"
    if use_concurrent is not None and use_concurrent == 'True':
        use_concurrent = True
    else:
        print(f"多账号执行间隔：{sleep_seconds}")
        use_concurrent = False
    # endregion
    execute()
