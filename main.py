# 设置日志，增加调试信息
from RouterSpeedLimitStrategy import RouterSpeedLimitStrategy

import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

from HonorRouterV4 import HonorRouterV4
# 初始化路由器控制
router = HonorRouterV4(
    ip="192.168.3.1",
    username="admin",
    password="123456"  # 替换为实际密码。猜一下手机号或者 123456，猜中之后就起飞了。
)

# 尝试登录
if router.login(max_retries=3):
    print("✓ 登录成功！")
    
    # 获取设备列表
    print("\n获取设备列表...")
    devices = router.get_host_info()  # 使用新的方法名
    if devices:
        # 启动心跳循环保持登录状态
        # print("\n启动心跳循环...")
        # router.start_heartbeat_loop(interval=5)
        
        # 启动策略执行循环（可选）
        print("\n启动策略执行循环...")
        strategy_executor = RouterSpeedLimitStrategy(router, config_path="config.json")
        strategy_executor.start_strategy_loop()
    
    # 退出
    router.logout()
else:
    print("✗ 登录失败，请检查密码和网络连接")