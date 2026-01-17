import json
import logging
from StatisticTool import StatisticTool
from Strategy import Strategy  # 修复：从Strategy模块导入Strategy类
import random
import time
from datetime import datetime
import threading
import hashlib
from collections import Counter

# 设置日志，增加调试信息
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class RouterSpeedLimitStrategy(Strategy):  # 现在正确继承Strategy类
    """
    路由器限速策略执行类
    根据配置文件执行不同时间段的限速策略
    """
    
    def __init__(self, router_instance, config_path="config.json"):
        """
        初始化策略执行器
        
        参数:
            router_instance: HonorRouterV4实例
            config_path: 配置文件路径
        """
        self.router = router_instance
        self.config_path = config_path
        self.config = self._load_config()
        
        # 初始化随机数种子以获得更好的随机性
        random.seed(None)  # 使用当前时间作为种子
        
        # 统计相关变量
        self.speed_statistics = {}  # 记录每种限速出现的次数
        self.last_write_time = time.time()  # 上次写文件的时间
        self.write_interval = 15 * 60  # 写文件间隔：15分钟
        self.lock = threading.Lock()  # 线程锁，确保统计安全

        self.statistic_tool = StatisticTool()
        self.statistic_tool._load_statistics()  # 加载已有统计
        
    def _load_config(self):
        """加载配置文件"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"加载配置文件失败: {e}")
            return {}
    
    def _load_statistics(self):
        """加载已有的统计信息"""
        try:
            with open("statistic.txt", 'r', encoding='utf-8') as f:
                self.speed_statistics = json.load(f)
        except FileNotFoundError:
            # 文件不存在，初始化为空字典
            self.speed_statistics = {}
        except Exception as e:
            logger.warning(f"加载统计文件失败，将重新开始统计: {e}")
            self.speed_statistics = {}
    
    def _save_statistics(self):
        """保存统计信息到文件"""
        try:
            with open("statistic.txt", 'w', encoding='utf-8') as f:
                json.dump(self.speed_statistics, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存统计文件失败: {e}")
    
    def _update_statistics(self, action):
        """更新统计信息"""
        with self.lock:
            # 获取上行速率值
            up_rate = action.get("DeviceMaxUpLoadRate", "0")
            
            # 更新统计
            if up_rate in self.speed_statistics:
                self.speed_statistics[up_rate] += 1
            else:
                self.speed_statistics[up_rate] = 1
    
    def _write_statistics_if_needed(self):
        """如果需要，写入统计文件（每15分钟一次）"""
        current_time = time.time()
        if current_time - self.last_write_time >= self.write_interval:
            self.statistic_tool._save_statistics()
            self.last_write_time = current_time
            logger.info(f"已保存统计信息到 {self.statistic_tool.filename}")
    
    def _get_current_time_range_strategy(self):
        """获取当前时间段对应的策略名称"""
        current_time = datetime.now().time()
        
        for time_range, strategy_name in self.config.get("timeRange2Strategy", {}).items():
            start_time_str, end_time_str = time_range.split('-')
            
            # 处理跨天的情况
            if end_time_str.startswith(':'):
                end_time_str = end_time_str[1:]  # 去掉冒号
            
            start_time = datetime.strptime(start_time_str, "%H:%M").time()
            end_time = datetime.strptime(end_time_str, "%H:%M").time()
            
            # 判断是否跨天
            if start_time <= end_time:  # 同一天内
                if start_time <= current_time <= end_time:
                    return strategy_name
            else:  # 跨天情况 (如 23:13-08:27)
                if current_time >= start_time or current_time <= end_time:
                    return strategy_name
        
        return None
    
    def _get_random_action_from_strategy(self, strategy_name):
        """从策略中随机获取一个动作"""
        strategy_list = self.config.get("strategyList", [])
        
        for strategy in strategy_list:
            if strategy.get("name") == strategy_name:
                action_list = strategy.get("actionList", [])
                if action_list:
                    return random.choice(action_list)
        
        return None
    
    def _execute_action_for_hosts(self, action):
        """为所有配置的主机执行动作"""
        # 获取当前主机信息
        hosts = self.router.get_host_info()
        if not hosts:
            logger.error("无法获取主机信息，跳过此次执行")
            return
        
        # 为IP列表中的主机执行策略
        host_ips = self.config.get("hostList", [])
        for ip in host_ips:
            # 验证主机是否在线
            host_exists = any(host.get("IPAddress") == ip and host.get("Active", False) for host in hosts)
            if host_exists:
                up_rate = int(action.get("DeviceMaxUpLoadRate", 0))
                down_rate = int(action.get("DeviceMaxDownLoadRate", 0))
                
                logger.info(f"为IP {ip} 执行限速策略: 上行{up_rate}kbps")
                success = self.router.set_device_speed_limit_by_ip(ip, up_rate, down_rate)
                if not success:
                    logger.error(f"为IP {ip} 设置限速失败")
            else:
                logger.warning(f"IP {ip} 不在线或不存在")
        
        # 为MAC列表中的主机执行策略
        mac_addresses = self.config.get("macList", [])
        for mac in mac_addresses:
            # 查找所有匹配此MAC地址的设备（可能有多个IP）
            matching_hosts = [host for host in hosts 
                             if host.get("MACAddress", "").lower() == mac.lower() and host.get("Active", False)]
            
            if not matching_hosts:
                logger.warning(f"MAC {mac} 不在线或不存在")
                continue
                
            up_rate = int(action.get("DeviceMaxUpLoadRate", 0))
            down_rate = int(action.get("DeviceMaxDownLoadRate", 0))
            
            # 为每个匹配的设备应用限速策略
            for host in matching_hosts:
                ip = host.get("IPAddress", "Unknown")
                logger.info(f"为MAC {mac} 的IP {ip} 执行限速策略: 上行{up_rate}kbps")
                
                success = self.router.set_device_speed_limit(mac, up_rate, down_rate)
                if not success:
                    logger.error(f"为MAC {mac} 设置限速失败")

    
    def _get_add_time(self):
        """从IntervalRange中获取正态分布的附加时间"""
        interval_range = self.config.get("IntervalRange", [-7, 285])
        min_val, max_val = interval_range[0], interval_range[1]
        
        # 使用正态分布随机生成附加时间
        mean = (min_val + max_val) / 2
        std_dev = (max_val - min_val) / 6  # 使99.7%的数据在范围内
        
        add_time = random.normalvariate(mean, std_dev)
        
        # 确保在范围内
        add_time = max(min_val, min(add_time, max_val))
        
        return add_time
    
    def start_strategy_loop(self):
        """
        开始策略执行循环
        """
        logger.info("开始执行限速策略循环...")
        
        while True:
            try:
                # 获取当前时间段对应的策略
                strategy_name = self._get_current_time_range_strategy()
                
                if strategy_name:
                    logger.info(f"当前时间段策略: {strategy_name}")
                    
                    # 从策略中随机获取一个动作
                    action = self._get_random_action_from_strategy(strategy_name)
                    
                    if action:
                        logger.info(f"执行动作: {action}")
                        
                        # 更新统计信息
                        self.statistic_tool._update_statistics(action)
                        
                        # 为所有配置的主机执行动作
                        self._execute_action_for_hosts(action)
                        
                        # 检查是否需要写入统计文件
                        self.statistic_tool._write_statistics_if_needed()
                    else:
                        logger.warning(f"策略 {strategy_name} 中没有找到可执行的动作")
                else:
                    logger.info(f"当前时间不在配置的时间范围内")
                
                # 计算等待时间
                base_interval = self.config.get("actionInterval", 15)
                add_time = self._get_add_time()
                total_wait = base_interval + add_time
                
                logger.info(f"等待 {total_wait:.2f} 秒后继续...")
                
                # 等待指定时间
                time.sleep(total_wait)
                
            except KeyboardInterrupt:
                logger.info("收到中断信号，退出策略执行循环")
                # 在退出前保存统计信息
                self.statistic_tool._save_statistics()
                logger.info("已保存最终统计信息到 statistic.txt")
                break
            except Exception as e:
                logger.error(f"策略执行循环中出现异常: {e}")
                # 发生异常时等待一段时间再继续
                time.sleep(10)
    
    def execute_once(self):
        """
        执行一次策略（非循环）
        """
        try:
            # 获取当前时间段对应的策略
            strategy_name = self._get_current_time_range_strategy()
            
            if strategy_name:
                logger.info(f"当前时间段策略: {strategy_name}")
                
                # 从策略中随机获取一个动作
                action = self._get_random_action_from_strategy(strategy_name)
                
                if action:
                    logger.info(f"执行动作: {action}")
                    
                    # 更新统计信息
                    self.statistic_tool._update_statistics(action)
                    
                    # 为所有配置的主机执行动作
                    self._execute_action_for_hosts(action)
                    
                    # 检查是否需要写入统计文件
                    self.statistic_tool._write_statistics_if_needed()
                else:
                    logger.warning(f"策略 {strategy_name} 中没有找到可执行的动作")
            else:
                logger.info(f"当前时间不在配置的时间范围内")
        except Exception as e:
            logger.error(f"执行策略时出现异常: {e}")

if __name__ == "__main__":
    # router_speed_limit_strategy = RouterSpeedLimitStrategy()
    # router_speed_limit_strategy._get_random_action_from_strategy("strategy3")
    
    # 创建一个函数来运行100次测试并统计结果
    def run_test_100_times():
        # 为了测试，我们创建一个模拟的router实例
        class MockRouter:
            pass
        
        # 使用默认配置文件路径
        router_speed_limit_strategy = RouterSpeedLimitStrategy(MockRouter(), "config.json")
        
        # 运行100次测试
        results = []
        for i in range(100):
            action = router_speed_limit_strategy._get_random_action_from_strategy("strategy3")
            if action:
                results.append(action)
        
        # 统计结果出现频次
        counter = Counter()
        for result in results:
            # 将字典转换为可哈希的元组以便计数
            action_tuple = tuple(sorted(result.items()))
            counter[action_tuple] += 1
        
        # 输出前十个结果
        print("前十个最常出现的结果:")
        for i, (action_tuple, count) in enumerate(counter.most_common(10), 1):
            action_dict = dict(action_tuple)
            print(f"{i}. {action_dict} - 出现次数: {count}")
        
        print(f"\n总共执行了100次，得到了 {len(counter)} 种不同的结果")
        
        return counter
    
    # 运行测试
    run_test_100_times()