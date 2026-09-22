"""运动员网络侵害处置中枢（harmhub）。

模块划分：
- config/contract：领域契约
- rules：版本化自动规则，只产出风险建议
- evidence：时间戳、内容哈希与保全回执
- workflow：线索归集、同源聚合、人工确认、申诉与规则升级
- api：HTTP 接口与分区授权
"""

from .workflow import Hub

__all__ = ["Hub"]
