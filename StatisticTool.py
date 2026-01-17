import json
import logging
# 设置日志，增加调试信息
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
import threading
import time
import json

class StatisticTool:
    """
    统计工具类
    用于记录和保存限速策略的执行统计信息
    """
    def __init__(self,filename="statistic.txt"):
        self.filename = filename
        self.lock = threading.Lock()  # 用于线程安全的更新

        self.speed_statistics = {}  # 记录每种限速出现的次数
        self.last_write_time = time.time()  # 上次写文件的时间
        self.write_interval = 15 * 60  # 写文件间隔：15分钟
        self.lock = threading.Lock()  # 线程锁，确保统计安全

    def _load_statistics(self):
        """加载已有的统计信息"""
        try:
            with open(self.filename, 'r', encoding='utf-8') as f:
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
            with open(self.filename, 'w', encoding='utf-8') as f:
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
            self._save_statistics()
            self.last_write_time = current_time
            logger.info(f"已保存统计信息到 {self.filename}")
    