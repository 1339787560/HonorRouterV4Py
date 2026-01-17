import requests
import logging
# 设置日志，增加调试信息
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Router:
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

    def login(self, max_retries=3):
        """
        主登录函数
        """
        if not self.password:
            raise ValueError("密码不能为空")
        
        for attempt in range(max_retries):
            logger.info(f"登录尝试 {attempt + 1}/{max_retries}")
            
            # 等待后重试
            if attempt < max_retries - 1:
                import time
                time.sleep(1)
        
        logger.error(f"登录失败，已重试{max_retries}次")
        return False
    
    def logout(self):
        """退出登录"""
        logger.info("已退出登录")

    def heartbeat(self):
        pass

    def get_host_info(self):
        pass

    def set_device_speed_limit(self, mac_address, up_rate_kbps=0, down_rate_kbps=0):
        pass

    def start_heartbeat_loop(self, interval=5):
        """
        启动心跳循环，保持登录状态
        """
        import threading
        import time
        
        def heartbeat_worker():
            while getattr(self, '_heartbeat_running', False):
                try:
                    self.heartbeat()
                    time.sleep(interval)
                except Exception as e:
                    logger.error(f"心跳循环异常: {e}")
                    break
        
        self._heartbeat_running = True
        self._heartbeat_thread = threading.Thread(target=heartbeat_worker, daemon=True)
        self._heartbeat_thread.start()
        logger.info(f"心跳循环已启动，间隔: {interval}秒")

    def stop_heartbeat_loop(self):
        """
        停止心跳循环
        """
        self._heartbeat_running = False
        if hasattr(self, '_heartbeat_thread'):
            self._heartbeat_thread.join(timeout=1)
        logger.info("心跳循环已停止")
