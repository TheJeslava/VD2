"""攻击面测绘（SurfaceMapper）：范围与攻击面。"""

from __future__ import annotations

import time

from ..indexer import attack_surface
from .base import AgentContext, AgentResult, BaseAgent


class SurfaceMapperAgent(BaseAgent):
    name = "surface_mapper"
    codename = "攻击面测绘"
    prompt_name = "surface_mapper.md"

    def run(self, ctx: AgentContext) -> AgentResult:
        started = time.time()
        result = AgentResult(name=self.name, codename=self.codename)
        if ctx.project.manifest.get("input_mode") == "url":
            target = ctx.project.target_url or ctx.project.zip_path
            surface = {
                "mode": "url",
                "target": target,
                "endpoint_count": len(ctx.project.endpoints),
                "endpoints": [endpoint.to_dict() for endpoint in ctx.project.endpoints[:200]],
                "awvs_provider": ctx.project.manifest.get("awvs_provider", ""),
                "awvs_raw_count": ctx.project.manifest.get("awvs_raw_count", 0),
                "entry_files": [],
                "source_hot_files": [],
                "sink_hot_files": [],
            }
            result.data.update({
                "surface": surface,
                "scope_summary": (
                    f"URL 模式：AWVS 来源 {surface['awvs_provider'] or 'unknown'}，"
                    f"目标 {target}，{len(ctx.project.endpoints)} 个动态候选端点。"
                ),
                "priority_areas": [],
                "entry_points": [endpoint.path for endpoint in ctx.project.endpoints[:30]],
                "risk_notes": ["动态候选没有源码位置；按 URL、请求通道与响应证据研判。"],
                "coverage_gaps": ["URL 模式不含源码数据流，无法证明 source→sink。"],
            })
            ctx.log(self.name, f"URL 模式：{len(ctx.project.endpoints)} 个候选端点")
            result.duration_sec = round(time.time() - started, 2)
            return result
        surface = attack_surface(ctx.project, ctx.contents)

        tree = [
            {"path": file.rel_path, "language": file.language, "lines": file.lines, "size": file.size}
            for file in ctx.project.files[:300]
        ]
        llm_data = self._llm_json(
            ctx,
            {
                "files": tree,
                "languages": ctx.project.languages,
                "frameworks": ctx.project.frameworks,
                "endpoints": [endpoint.to_dict() for endpoint in ctx.project.endpoints[:120]],
                "source_hot_files": surface.get("source_hot_files", []),
                "sink_hot_files": surface.get("sink_hot_files", []),
                "quarantined_files": sorted(ctx.quarantined),
            },
            label="scope",
            max_chars=20000,
        )
        if llm_data:
            result.used_llm = True
            allowed = ctx.allowed_files
            priority = []
            for item in llm_data.get("priority_areas", [])[:12]:
                files = [path for path in item.get("files", []) if path in allowed]
                if files:
                    priority.append({"area": str(item.get("area", ""))[:200], "files": files[:8],
                                     "reason": str(item.get("reason", ""))[:500],
                                     "priority": item.get("priority", 99)})
            review_items = []
            for item in llm_data.get("medium_review_items", [])[:20]:
                if not isinstance(item, dict):
                    continue
                path = str(item.get("file", ""))
                if path not in allowed:
                    continue
                review_items.append({
                    "type": str(item.get("type", ""))[:60],
                    "file": path,
                    "reason": str(item.get("reason", ""))[:400],
                })
            result.data.update({
                "scope_summary": llm_data.get("scope_summary", ""),
                "priority_areas": priority,
                "entry_points": llm_data.get("entry_points", [])[:30],
                "risk_notes": llm_data.get("risk_notes", [])[:20],
                "coverage_gaps": llm_data.get("coverage_gaps", [])[:20],
                "medium_review_items": review_items,
            })
        else:
            frameworks = ", ".join(ctx.project.frameworks) or "未识别"
            result.data.update({
                "scope_summary": f"项目包含 {len(ctx.project.files)} 个文件，语言 {', '.join(sorted(ctx.project.languages)) or '未知'}，框架 {frameworks}，共识别 {len(ctx.project.endpoints)} 个 HTTP 端点。",
                "priority_areas": self._fallback_priority(surface),
                "entry_points": [endpoint.path for endpoint in ctx.project.endpoints[:30]],
                "risk_notes": ["优先审计直接接收外部输入的端点与文件操作"],
                "coverage_gaps": ["仅源码，缺少部署配置与运行时信息"],
            })
        # LLM 的攻击面观察必须可被下游消费、可落盘；否则“模型看见了但没人用”。
        ctx.project.manifest["surface_notes"] = {
            "scope_summary": result.data.get("scope_summary", ""),
            "priority_areas": result.data.get("priority_areas", [])[:12],
            "risk_notes": result.data.get("risk_notes", [])[:20],
            "coverage_gaps": result.data.get("coverage_gaps", [])[:20],
            "medium_review_items": result.data.get("medium_review_items", [])[:20],
        }
        ctx.log(self.name, f"识别 {len(ctx.project.endpoints)} 个端点、{len(ctx.project.frameworks)} 个框架")
        result.duration_sec = round(time.time() - started, 2)
        return result

    @staticmethod
    def _fallback_priority(surface: dict) -> list[dict]:
        areas = []
        for path, count in surface.get("source_hot_files", [])[:6]:
            areas.append({"area": "外部输入入口", "files": [path], "reason": f"{count} 处 source 调用", "priority": 1})
        for path, count in surface.get("sink_hot_files", [])[:6]:
            areas.append({"area": "危险汇点", "files": [path], "reason": f"{count} 处 sink 调用", "priority": 2})
        return areas
