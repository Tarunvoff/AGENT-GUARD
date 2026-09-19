"""Tool execution interception and runtime policy enforcement wrapper."""

import functools
import inspect
import time
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Union

from agentguard.context.context import Context
from agentguard.context.provenance import ContextSource
from agentguard.context.taint import TaintState
from agentguard.decisions.decision import DecisionAction, SecurityDecision
from agentguard.tools.tool import Resource, SensitivityLevel, ToolDefinition, ToolRequest, ToolResult
from agentguard.tracing.correlation import generate_id, get_current_context
from agentguard.tracing.events import EventType

if TYPE_CHECKING:
    from agentguard.client import AgentGuard


def protected_tool(
    guard: "AgentGuard",
    name: Optional[str] = None,
    description: str = "",
    sensitivity: SensitivityLevel = SensitivityLevel.MEDIUM,
    required_capabilities: Optional[List[str]] = None,
    classification: str = "internal",
    target_resources: Optional[List[Resource]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator to register and wrap a tool function with AgentGuard security enforcement."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        tool_name = name or fn.__name__
        tool_desc = description or fn.__doc__ or ""
        req_caps = required_capabilities or []
        res_list = target_resources or []

        tool_def = ToolDefinition(
            tool_id=generate_id("tool"),
            name=tool_name,
            description=tool_desc,
            sensitivity=sensitivity,
            required_capabilities=req_caps,
            classification=classification,
            target_resources=res_list,
            metadata=metadata or {},
        )

        guard.register_tool(tool_def)

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                return await _execute_protected_tool_async(guard, tool_def, fn, *args, **kwargs)
            async_wrapper.tool_def = tool_def  # type: ignore
            return async_wrapper
        else:
            @functools.wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                return _execute_protected_tool_sync(guard, tool_def, fn, *args, **kwargs)
            sync_wrapper.tool_def = tool_def  # type: ignore
            return sync_wrapper

    return decorator


def _prepare_tool_request(
    guard: "AgentGuard",
    tool_def: ToolDefinition,
    fn: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> ToolRequest:
    ctx = get_current_context()
    agent_id = ctx.agent_id if ctx else None
    
    # Map positional args to param names
    sig = inspect.signature(fn)
    bound_args = sig.bind_partial(*args, **kwargs)
    bound_args.apply_defaults()
    raw_arguments = dict(bound_args.arguments)

    # Sanitize arguments for logging/event storage
    safe_arguments = guard.config.sanitize(raw_arguments)

    context_ids = []
    if ctx and ctx.context_id:
        context_ids.append(ctx.context_id)

    target_res = tool_def.target_resources[0] if tool_def.target_resources else None

    return ToolRequest(
        request_id=generate_id("req"),
        tool_id=tool_def.tool_id,
        tool_name=tool_def.name,
        agent_id=agent_id,
        arguments=safe_arguments,
        context_ids=context_ids,
        target_resource=target_res,
    )


def _execute_protected_tool_sync(
    guard: "AgentGuard",
    tool_def: ToolDefinition,
    fn: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> Any:
    request = _prepare_tool_request(guard, tool_def, fn, *args, **kwargs)
    ctx = get_current_context()

    # Emit tool.requested
    guard.emit_event(
        event_type=EventType.TOOL_REQUESTED,
        agent_id=request.agent_id,
        payload={
            "tool_id": tool_def.tool_id,
            "tool_name": tool_def.name,
            "arguments": request.arguments,
            "sensitivity": tool_def.sensitivity.value,
        }
    )

    # Emit resource.access_requested if applicable
    if request.target_resource:
        guard.emit_event(
            event_type=EventType.RESOURCE_ACCESS_REQUESTED,
            agent_id=request.agent_id,
            payload={
                "resource_id": request.target_resource.resource_id,
                "resource_name": request.target_resource.name,
                "sensitivity": request.target_resource.sensitivity.value,
            }
        )

    # Evaluate security policy
    decision: SecurityDecision = guard.evaluate_tool_invocation(tool_def, request)

    if decision.is_blocked:
        raise PermissionError(
            f"AgentGuard Policy Enforced: Tool '{tool_def.name}' invocation BLOCKED. "
            f"Reason: [{decision.reason_code}] {decision.explanation}"
        )

    start_t = time.perf_counter()
    err_str = None
    try:
        raw_output = fn(*args, **kwargs)
        elapsed_ms = (time.perf_counter() - start_t) * 1000
        output_for_event = guard.config.sanitize(raw_output)
        
        # Emit tool.invoked
        guard.emit_event(
            event_type=EventType.TOOL_INVOKED,
            agent_id=request.agent_id,
            payload={
                "tool_id": tool_def.tool_id,
                "tool_name": tool_def.name,
                "success": True,
                "execution_time_ms": elapsed_ms,
                "output_summary": str(output_for_event)[:200],
            }
        )
        return raw_output
    except Exception as e:
        elapsed_ms = (time.perf_counter() - start_t) * 1000
        err_str = str(e)
        guard.emit_event(
            event_type=EventType.TOOL_INVOKED,
            agent_id=request.agent_id,
            payload={
                "tool_id": tool_def.tool_id,
                "tool_name": tool_def.name,
                "success": False,
                "error": err_str,
                "execution_time_ms": elapsed_ms,
            }
        )
        raise


async def _execute_protected_tool_async(
    guard: "AgentGuard",
    tool_def: ToolDefinition,
    fn: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> Any:
    request = _prepare_tool_request(guard, tool_def, fn, *args, **kwargs)

    # Emit tool.requested
    guard.emit_event(
        event_type=EventType.TOOL_REQUESTED,
        agent_id=request.agent_id,
        payload={
            "tool_id": tool_def.tool_id,
            "tool_name": tool_def.name,
            "arguments": request.arguments,
            "sensitivity": tool_def.sensitivity.value,
        }
    )

    if request.target_resource:
        guard.emit_event(
            event_type=EventType.RESOURCE_ACCESS_REQUESTED,
            agent_id=request.agent_id,
            payload={
                "resource_id": request.target_resource.resource_id,
                "resource_name": request.target_resource.name,
                "sensitivity": request.target_resource.sensitivity.value,
            }
        )

    decision: SecurityDecision = guard.evaluate_tool_invocation(tool_def, request)

    if decision.is_blocked:
        raise PermissionError(
            f"AgentGuard Policy Enforced: Tool '{tool_def.name}' invocation BLOCKED. "
            f"Reason: [{decision.reason_code}] {decision.explanation}"
        )

    start_t = time.perf_counter()
    try:
        raw_output = await fn(*args, **kwargs)
        elapsed_ms = (time.perf_counter() - start_t) * 1000
        output_for_event = guard.config.sanitize(raw_output)

        guard.emit_event(
            event_type=EventType.TOOL_INVOKED,
            agent_id=request.agent_id,
            payload={
                "tool_id": tool_def.tool_id,
                "tool_name": tool_def.name,
                "success": True,
                "execution_time_ms": elapsed_ms,
                "output_summary": str(output_for_event)[:200],
            }
        )
        return raw_output
    except Exception as e:
        elapsed_ms = (time.perf_counter() - start_t) * 1000
        guard.emit_event(
            event_type=EventType.TOOL_INVOKED,
            agent_id=request.agent_id,
            payload={
                "tool_id": tool_def.tool_id,
                "tool_name": tool_def.name,
                "success": False,
                "error": str(e),
                "execution_time_ms": elapsed_ms,
            }
        )
        raise
