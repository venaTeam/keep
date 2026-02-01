import logging
import keep.common.logging
from keep.common.core.config import starlette_config
from keep.identitymanager.identitymanagerfactory import IdentityManagerTypes

# We read AUTH_TYPE directly to avoid importing keep.api.api which triggers a cascade of imports
# that might fail during early startup or in restricted environments.
# Using cast=str to ensure we always get a string, enforcing type if passing objects by mistake
AUTH_TYPE = starlette_config("AUTH_TYPE", default=IdentityManagerTypes.NOAUTH.value, cast=str).lower()

keep.common.logging.setup_logging()
logger = logging.getLogger(__name__)



def on_starting(server=None):
    """This function is called by the gunicorn server when it starts"""
    from keep.common.core.init import init_services
    from keep.api.routes.dashboard import provision_dashboards
    
    init_services(auth_type=AUTH_TYPE, provision_dashboards_func=provision_dashboards)


def post_worker_init(worker):
    # We need to reinitialize logging in each worker because gunicorn forks the worker processes
    print("Init logging in worker")
    logging.getLogger().handlers = []  # noqa
    keep.common.logging.setup_logging()  # noqa
    print("Logging initialized in worker")


post_worker_init = post_worker_init
