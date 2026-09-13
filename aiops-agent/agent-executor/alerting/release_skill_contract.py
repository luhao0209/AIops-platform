from __future__ import annotations


RELEASE_REGRESSION_SKILL = "release_regression"
ACTIVATE_RELEASE_SKILL_TOOL = "activate_release_regression_skill"
REQUEST_ROLLBACK_APPROVAL_TOOL = "request_rollback_approval"
INCIDENT_WORKFLOW_TOOL_NAMES = {
    ACTIVATE_RELEASE_SKILL_TOOL,
    REQUEST_ROLLBACK_APPROVAL_TOOL,
}

RELEASE_SKILL_INSTRUCTIONS = (
    "已进入 release_regression Skill。接下来只围绕发布回归假设补证据："
    "确认影响指标、具体错误日志、相关镜像变更、异常对象与新版本的对应关系，"
    "并确认上一稳定镜像。不要为了追查数据库最深层原因而阻塞可逆止血。"
    "证据足以支持回滚时，调用 request_rollback_approval 创建人工审批；"
    "证据反驳发布假设时应明确退出该方向并继续通用调查。"
)
