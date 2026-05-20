from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import logging

logger = logging.getLogger(__name__)

async def set_rls_context(session: AsyncSession, user_id: str, roles: str, request_id: str):
    """
    Set transaction-local RLS context variables.
    """
    try:
        # Use set_config with is_local=true to ensure context only applies to the current transaction
        await session.execute(text("SELECT set_config('app.current_user_id', :user_id, true)"), {"user_id": user_id})
        await session.execute(text("SELECT set_config('app.current_roles', :roles, true)"), {"roles": roles})
        if request_id:
            await session.execute(text("SELECT set_config('app.request_id', :request_id, true)"), {"request_id": request_id})
    except Exception as e:
        logger.error(f"Failed to set RLS context: {e}")
        raise
