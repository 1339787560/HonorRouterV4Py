import requests
import json
import hashlib
import base64
import binascii
import secrets
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from bs4 import BeautifulSoup

from Router import Router
from Crypto.Hash import SHA256
# 设置日志，增加调试信息
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class HonorRouterV4(Router):
    def __init__(self, ip="192.168.3.1", username="admin", password=None):
        """
        初始化荣耀路由器4控制类
        
        参数:
            ip: 路由器IP地址
            username: 用户名，通常是admin
            password: 密码，默认路由器背面
        """
        self.base_url = f"http://{ip}"
        self.username = username
        self.password = password
        self.session = requests.Session()
        
        # 设置请求头
        self.session.headers.update({
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Content-Type': 'application/json; charset=UTF-8',
            'X-Requested-With': 'XMLHttpRequest',
            '_ResponseFormat': 'JSON',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Origin': self.base_url,
            'Referer': f'{self.base_url}/html/index.html',
        })
        
        # SCRAM相关参数
        self.first_nonce = None
        self.salt = None
        self.iterations = None
        self.server_nonce = None
        self.rsan = None
        self.rsae = None
        
        # 心跳控制变量
        self._heartbeat_running = False
        self._heartbeat_thread = None
    
    def _generate_nonce(self, length=16):
        """生成随机nonce（十六进制字符串）"""
        return secrets.token_hex(length)
    
    def _hex_to_bytes(self, hex_str):
        """十六进制字符串转字节"""
        return binascii.unhexlify(hex_str)
    
    def _bytes_to_hex(self, data):
        """字节转十六进制字符串"""
        return binascii.hexlify(data).decode('utf-8')
    
    def hmac_sha256(self,key, message):
        block_size = 64  # SHA-256分组长度
        # 确保key是bytes类型
        if isinstance(key, str):
            key = key.encode('utf-8')
        # 密钥预处理
        if len(key) > block_size:
            key = hashlib.sha256(key).digest()
        key = key.ljust(block_size, b'\x00')

        # 生成填充值
        ipad = bytes([x ^ 0x36 for x in key])
        opad = bytes([x ^ 0x5C for x in key])

        # 计算内层哈希
        inner_hash = hashlib.sha256(ipad + message).digest()

        # 计算外层哈希
        return hashlib.sha256(opad + inner_hash).hexdigest()
    
    def _sha256(self, data):
        """SHA256计算"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).digest()
    
    def _pbkdf2_hmac_sha256(self, password, salt, iterations):
        """PBKDF2-HMAC-SHA256密钥派生"""
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        # 使用Crypto库的PBKDF2，指定SHA256作为哈希模块
        dk = PBKDF2(password, salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)
        return dk
    
    def _xor_bytes(self, a, b):
        """字节数组异或运算"""
        return bytes([x ^ y for x, y in zip(a, b)])

    def _extract_csrf_from_html(self, html_content):
        """
        从HTML内容中提取CSRF参数
        对应前端代码中的utilGetCsrf函数
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # 提取meta标签中的CSRF参数
        csrf_param = None
        csrf_token = None
        
        # 查找csrf_param的meta标签
        meta_param = soup.find('meta', {'name': 'csrf_param'})
        if meta_param:
            csrf_param = meta_param.get('content')
            logger.debug(f"从meta标签提取到csrf_param: {csrf_param}")
        
        # 查找csrf_token的meta标签
        meta_token = soup.find('meta', {'name': 'csrf_token'})
        if meta_token:
            csrf_token = meta_token.get('content')
            logger.debug(f"从meta标签提取到csrf_token: {csrf_token}")
        
        # 检查是否都找到了
        if csrf_param and csrf_token:
            self.csrf_param = csrf_param
            self.csrf_token = csrf_token
            return True
        else:
            logger.warning(f"无法从HTML中提取CSRF参数: csrf_param={csrf_param}, csrf_token={csrf_token}")
            return False

    def get_initial_csrf(self):
        """
        获取初始CSRF参数
        对应前端页面加载时自动获取CSRF参数的逻辑
        """
        # 第一步：尝试从HTML页面中提取CSRF参数
        html_url = f"{self.base_url}/html/index.html"
        
        try:
            logger.info("尝试从HTML页面中提取CSRF参数...")
            # 先获取HTML页面
            self.session.headers.update({'Accept': 'text/html'})
            response = self.session.get(html_url, timeout=10)
            response.raise_for_status()
            
            # 从HTML中提取CSRF参数
            if self._extract_csrf_from_html(response.text):
                logger.info("成功从HTML页面提取CSRF参数")
                return True
            else:
                logger.warning("从HTML页面提取CSRF失败，尝试备选方案...")
        except Exception as e:
            logger.error(f"从HTML页面获取CSRF异常: {e}")
            logger.info("尝试备选方案...")
        finally:
            # 恢复原来的请求头
            self.session.headers.update({'Accept': 'application/json, text/javascript, */*; q=0.01'})
        
        # 第二步：备选方案 - 发送空的POST请求获取CSRF参数
        api_url = f"{self.base_url}/api/system/user_login_nonce"
        
        try:
            logger.info("尝试通过API请求获取CSRF参数...")
            # 发送空的POST请求获取初始CSRF参数
            response = self.session.post(api_url, json={}, timeout=10)
            response.raise_for_status()
            
            result = response.json()
            logger.debug(f"API CSRF响应: {json.dumps(result, indent=2)}")
            
            if result.get("err") == 0:
                # 保存CSRF参数
                self.csrf_token = result.get("csrf_token", "")
                self.csrf_param = result.get("csrf_param", "")
                
                if not all([self.csrf_token, self.csrf_param]):
                    raise ValueError("服务器响应缺少CSRF参数")
                
                logger.info("成功通过API获取CSRF参数")
                logger.debug(f"csrf_token: {self.csrf_token}, csrf_param: {self.csrf_param}")
                return True
            else:
                logger.error(f"API获取CSRF失败: {result}")
                return False
                
        except Exception as e:
            logger.error(f"API获取CSRF异常: {e}")
            return False
    
    def get_login_nonce(self):
        """
        第一步：获取nonce、salt等参数
        对应前端代码中的 user_login_nonce
        """
        self.first_nonce = self._generate_nonce(16)
        
        data = {
            "username": self.username,
            "firstnonce": self.first_nonce
        }
        
        # 构建包含CSRF参数的完整payload
        payload = {
            "data": data,
            "csrf": {
                "csrf_param": self.csrf_param,
                "csrf_token": self.csrf_token
            }
        }
        
        url = f"{self.base_url}/api/system/user_login_nonce"
        
        try:
            response = self.session.post(url, json=payload, timeout=10)
            response.raise_for_status()
            
            result = response.json()
            logger.debug(f"nonce响应: {json.dumps(result, indent=2)}")
            
            if result.get("err") == 0:
                # 保存服务器返回的参数
                self.salt = result.get("salt", "")
                self.iterations = result.get("iterations", 4096)
                self.server_nonce = result.get("servernonce", "")
                
                # 更新CSRF参数
                self.csrf_token = result.get("csrf_token", "")
                self.csrf_param = result.get("csrf_param", "")
                
                if not all([self.salt, self.server_nonce, self.csrf_token, self.csrf_param]):
                    raise ValueError("服务器响应缺少必要参数")
                
                logger.info("成功获取登录参数")
                logger.debug(f"salt: {self.salt}, iterations: {self.iterations}, server_nonce: {self.server_nonce}")
                logger.debug(f"csrf_token: {self.csrf_token}, csrf_param: {self.csrf_param}")
                return True
            else:
                logger.error(f"获取nonce失败: {result}")
                return False
                
        except Exception as e:
            logger.error(f"获取nonce异常: {e}")
            return False
    
    def calculate_scram_proofs(self):
        """
            第二步：计算SCRAM证明
            对应前端代码中的计算部分
            与JavaScript的CryptoJS.SCRAM实现保持一致
        """
        if not all([self.first_nonce, self.salt, self.iterations, self.server_nonce]):
            raise ValueError("缺少必要的SCRAM参数")

        # 根据JavaScript示例，构造auth_msg
        auth_msg = f"{self.first_nonce},{self.server_nonce},{self.server_nonce}"
        logger.debug(f"Auth Message: {auth_msg}")

        # 1. 将salt从十六进制字符串转换为字节（类似CryptoJS.enc.Hex.parse）
        salt_bytes = self._hex_to_bytes(self.salt)
        # 2. 计算SaltedPassword - 使用PBKDF2（类似scram.saltedPassword）
        logger.debug(f"计算SaltedPassword，密码: {self.password}, salt: {self.salt}, iterations: {self.iterations}")
        salted_password = self._pbkdf2_hmac_sha256(
            self.password.encode('utf-8'),
            salt_bytes,
            self.iterations
        )
        logger.debug(f"SaltedPassword: {self._bytes_to_hex(salted_password)}")

        # 3. 计算ClientKey - HMAC(salted_password, "Client Key")
        client_key_hex 	= self.hmac_sha256("Client Key",salted_password)
        client_key 		= bytes.fromhex(client_key_hex)
        
        logger.debug(f"ClientKey: {client_key_hex}")

        # 4. 计算StoredKey - SHA256(client_key)（类似scram.storedKey）
        stored_key 		= self._sha256(client_key)
        stored_key_hex 	= self._bytes_to_hex(stored_key)
        logger.debug(f"StoredKey: {stored_key_hex}")

        # 5. 计算ServerKey - HMAC(salted_password, "Server Key")
        server_key_hex = self.hmac_sha256("Server Key",salted_password)
        server_key = bytes.fromhex(server_key_hex)
        logger.debug(f"ServerKey: {server_key_hex}")

        # 6. 计算ClientSignature - HMAC(stored_key, auth_msg)（类似scram.signature）
        client_signature_hex 	= self.hmac_sha256(auth_msg,stored_key)
        client_signature 		= bytes.fromhex(client_signature_hex)
        logger.debug(f"ClientSignature: {client_signature_hex}")

        # 在CryptoJS中，数据以32位字（words）为单位进行操作
        client_proof = self._xor_bytes(client_key, client_signature)
        client_proof_hex = self._bytes_to_hex(client_proof)
        logger.debug(f"ClientProof: {client_proof_hex}")

        # 8. 计算ServerProof用于验证 - HMAC(server_key, auth_msg)
        server_proof_hex = self.hmac_sha256(auth_msg,server_key)
        server_proof = bytes.fromhex(server_proof_hex)
        logger.debug(f"ServerProof: {server_proof_hex}")

        return {
            "client_proof": client_proof_hex,
            "server_key": server_key,
            "server_proof": server_proof_hex,
            "auth_msg": auth_msg
        }

    def submit_login_proof(self, client_proof):
        """
        第三步：提交client proof完成登录
        对应前端代码中的 user_login_proof
        
        关键修复：final_nonce只使用服务器返回的nonce，与JavaScript代码保持一致
        """
        # 构造正确的finalnonce - 只使用服务器返回的nonce（关键修复）
        # JavaScript代码中：var finalNonce = res['servernonce'];
        final_nonce = self.server_nonce
        
        data = {
            "clientproof": client_proof,
            "finalnonce": final_nonce
        }
        
        # 构建包含CSRF参数的完整payload
        payload = {
            "data": data,
            "csrf": {
                "csrf_param": self.csrf_param,
                "csrf_token": self.csrf_token
            }
        }
        
        url = f"{self.base_url}/api/system/user_login_proof"
        
        try:
            logger.debug(f"提交登录proof: clientproof={client_proof}, finalnonce={final_nonce}")
            logger.debug(f"CSRF参数: {json.dumps(payload['csrf'])}")
            
            response = self.session.post(url, json=payload, timeout=10)
            response.raise_for_status()
            
            result = response.json()
            logger.debug(f"proof响应: {json.dumps(result, indent=2)}")
            
            if result.get("err") == 0:
                # 保存加密参数
                self.rsan = result.get("rsan")
                self.rsae = result.get("rsae")

                # 更新 csrf 信息。
                self.session.cookies.set('csrf_param', result['csrf_param'])
                self.session.cookies.set('csrf_token', result['csrf_token'])
                
                logger.info("登录成功！")
                logger.info(f"获取到加密参数: rsan={self.rsan[:20]}..., rsae={self.rsae}")
                return True, result
            else:
                error_msg = f"登录失败: {result.get('errmsg', '未知错误')}, 错误码: {result.get('err')}"
                logger.error(error_msg)
                return False, result
                
        except Exception as e:
            error_msg = f"提交proof异常: {e}"
            logger.error(error_msg)
            return False, {"error": str(e)}
    
    def login(self, max_retries=3):
        """
        主登录函数
        """
        if not self.password:
            raise ValueError("密码不能为空")
        
        for attempt in range(max_retries):
            logger.info(f"登录尝试 {attempt + 1}/{max_retries}")
            
            try:
                # 步骤0: 先获取初始CSRF参数（关键修复）
                if not self.get_initial_csrf():
                    logger.warning("获取初始CSRF失败，重试...")
                    continue
                
                # 步骤1: 获取nonce
                if not self.get_login_nonce():
                    logger.warning("获取nonce失败，重试...")
                    continue
                
                # 步骤2: 计算SCRAM证明
                scram_data = self.calculate_scram_proofs()
                
                # 步骤3: 提交proof
                success, result = self.submit_login_proof(scram_data["client_proof"])
                
                if success:
                    logger.info(f"登录成功！SessionID: {self.session.cookies.get('SessionID_R3', 'Not found')}")
                    return True
                else:
                    logger.warning(f"登录失败: {result}")
                    
            except Exception as e:
                logger.error(f"登录过程异常: {e}")
            
            # 等待后重试
            if attempt < max_retries - 1:
                import time
                time.sleep(1)
        
        logger.error(f"登录失败，已重试{max_retries}次")
        return False
    
    def _encrypt_password(self, password, rsa_n, rsa_e):
        """
        使用RSA公钥加密密码
        用于其他需要加密的请求
        """
        try:
            # 构建RSA公钥
            n = int(rsa_n, 16)
            e = int(rsa_e, 16)
            
            rsa_key = RSA.construct((n, e))
            cipher = PKCS1_v1_5.new(rsa_key)
            
            # 加密密码
            encrypted = cipher.encrypt(password.encode('utf-8'))
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            logger.error(f"RSA加密失败: {e}")
            return None
    def logout(self):
        """退出登录"""
        try:
            url = f"{self.base_url}/api/system/user_logout"
            payload = {"name": "user_logout", "data": {}}
            
            response = self.session.post(url, json=payload, timeout=5)
            if response.status_code == 200:
                logger.info("已退出登录")
        except Exception as e:
            logger.error(f"退出登录异常: {e}")
        finally:
            self.session.close()

    def heartbeat(self):
        """
            发送心跳包，保持登录状态
            对应接口: http://192.168.3.1/api/system/heartbeat
        """
        if not self.session.cookies.get('SessionID_R3'):
            logger.error("未登录，请先调用login()")
            return None
        
        url = f"{self.base_url}/api/system/heartbeat"
        
        try:
            response = self.session.get(url, timeout=5)
            response.raise_for_status()
            
            result = response.json()
            logger.debug(f"心跳响应: {result}")
            return result
        except Exception as e:
            logger.error(f"心跳请求失败: {e}")
            return None

    def get_host_info(self):
        """
        获取主机信息列表
        对应接口: http://192.168.3.1/api/system/HostInfo
        """
        if not self.session.cookies.get('SessionID_R3'):
            logger.error("未登录，请先调用login()")
            return None
        
        url = f"{self.base_url}/api/system/HostInfo"
        
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            hosts = response.json()
            logger.info(f"获取到 {len(hosts)} 个设备信息")
            return hosts
        except Exception as e:
            logger.error(f"获取主机信息失败: {e}")
            self.login()
            return None

    def set_device_speed_limit(self, mac_address, up_rate_kbps=0, down_rate_kbps=0):
        """
        设置设备限速
        
        参数:
            mac_address: 设备MAC地址
            up_rate_kbps: 上行限速(kbps)，0表示不限速
            down_rate_kbps: 下行限速(kbps)，0表示不限速
        对应接口: http://192.168.3.1/api/app/qosclass_host
        """
        if not self.session.cookies.get('SessionID_R3'):
            logger.error("未登录，请先调用login()")
            return False
        
        # 首先获取设备信息以获取完整设备数据
        hosts = self.get_host_info()
        if not hosts:
            logger.error("无法获取设备列表，无法设置限速")
            return False
        
        # 查找指定MAC地址的设备
        target_device = None
        for host in hosts:
            if host.get("MACAddress", "").lower() == mac_address.lower():
                target_device = host
                break
        
        if not target_device:
            logger.error(f"未找到MAC地址为 {mac_address} 的设备")
            return False
        
        # 更新限速参数
        target_device["DeviceMaxUpLoadRate"] = up_rate_kbps
        target_device["DeviceMaxDownLoadRate"] = down_rate_kbps
        target_device["DeviceDownRateEnable"] = True
        
        # 构建请求数据
        payload = {
            "data": target_device,
            "csrf": {
                "csrf_param": self.session.cookies.get('csrf_param', ''),
                "csrf_token": self.session.cookies.get('csrf_token', '')
            }
        }
        
        url = f"{self.base_url}/api/app/qosclass_host"
        
        try:
            result = self._csrf_post(url, json_data=payload, timeout=10)
            logger.info(f"限速设置响应: {result}")
            
            if isinstance(result, dict) and result.get("errcode") == 0:
                logger.info(f"成功为设备 {mac_address}（IP：{target_device["IPAddress"]}） 设置限速: 上行{up_rate_kbps}kbps, 下行{down_rate_kbps}kbps")
                return True
            else:
                logger.error(f"限速设置失败: {result}")
                return False
        except Exception as e:
            logger.error(f"设置设备限速失败: {e}")
            return False
    def _csrf_post(self, url, data=None, json_data=None, timeout=10):
        """
        封装的POST请求，自动处理CSRF参数更新
        如果响应包含csrf_param和csrf_token，会自动更新到会话中
        """
        try:
            if json_data is not None:
                response = self.session.post(url, json=json_data, timeout=timeout)
            elif data is not None:
                response = self.session.post(url, data=data, timeout=timeout)
            else:
                response = self.session.post(url, timeout=timeout)
            
            response.raise_for_status()
            
            # 检查响应是否为JSON
            try:
                result = response.json()
                
                # 如果响应中包含csrf参数，更新到会话中
                if isinstance(result, dict):
                    # 检查响应中是否直接包含csrf参数
                    if 'csrf_param' in result and 'csrf_token' in result:
                        self.session.cookies.set('csrf_param', result['csrf_param'])
                        self.session.cookies.set('csrf_token', result['csrf_token'])
                        logger.debug(f"更新CSRF参数: param={result['csrf_param']}, token={result['csrf_token']}")
                    
                    # 检查响应中的data字段是否包含csrf参数
                    if 'data' in result and isinstance(result['data'], dict):
                        data = result['data']
                        if 'csrf_param' in data and 'csrf_token' in data:
                            self.session.cookies.set('csrf_param', data['csrf_param'])
                            self.session.cookies.set('csrf_token', data['csrf_token'])
                            logger.debug(f"从data字段更新CSRF参数: param={data['csrf_param']}, token={data['csrf_token']}")
                
                return result
            except ValueError:
                # 响应不是JSON格式，直接返回文本
                return response.text
                
        except Exception as e:
            logger.error(f"POST请求失败 {url}: {e}")
            raise

    def set_device_speed_limit_by_ip(self, ip_address, up_rate_kbps=0, down_rate_kbps=0):
        """
        根据IP地址设置设备限速
        
        参数:
            ip_address: 设备IP地址
            up_rate_kbps: 上行限速(kbps)，0表示不限速
            down_rate_kbps: 下行限速(kbps)，0表示不限速
        """
        if not self.session.cookies.get('SessionID_R3'):
            logger.error("未登录，请先调用login()")
            return False
        
        # 首先获取设备列表以获取完整设备数据
        hosts = self.get_host_info()
        if not hosts:
            logger.error("无法获取设备列表，无法设置限速")
            return False
        
        # 查找指定IP地址的设备
        target_device = None
        for host in hosts:
            if host.get("IPAddress", "") == ip_address:
                target_device = host
                break
        
        if not target_device:
            logger.error(f"未找到IP地址为 {ip_address} 的设备")
            return False
        
        # 更新限速参数
        target_device["DeviceMaxUpLoadRate"] = up_rate_kbps
        target_device["DeviceMaxDownLoadRate"] = down_rate_kbps
        target_device["DeviceDownRateEnable"] = True
        
        # 构建请求数据
        payload = {
            "data": target_device,
            "csrf": {
                "csrf_param": self.session.cookies.get('csrf_param', ''),
                "csrf_token": self.session.cookies.get('csrf_token', '')
            }
        }
        
        url = f"{self.base_url}/api/app/qosclass_host"
        
        try:
            result = self._csrf_post(url, json_data=payload, timeout=10)
            logger.info(f"限速设置响应: {result}")
            
            if isinstance(result, dict) and result.get("errcode") == 0:
                logger.info(f"成功为设备 {target_device["mac_address"]}（IP：{ip_address}） 设置限速: 上行{up_rate_kbps}kbps, 下行{down_rate_kbps}kbps")
                return True
            else:
                logger.error(f"限速设置失败: {result}")
                return False
        except Exception as e:
            logger.error(f"设置设备限速失败: {e}")
            return False
    