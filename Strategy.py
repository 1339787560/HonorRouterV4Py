import time

class Strategy:
    """
        限速策略抽象类。
    """

    def start_strategy_loop(self):
        while True:
            self.execute_once()
            time.sleep(60)  # 每分钟执行一次
    
    def execute_once(self):
        pass