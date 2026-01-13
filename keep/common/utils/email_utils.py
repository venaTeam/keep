import enum
import logging

from keep.common.core.config import config

# TODO
# This is beta code. It will be changed in the future.

# Sending emails mechanism is currently disabled/removed as SendGrid dependency was removed.
# Future implementation should support SMTP/generic email providers.

# In the OSS - you can overwrite the template ids
class EmailTemplates(enum.Enum):
    WORKFLOW_RUN_FAILED = config(
        "WORKFLOW_FAILED_EMAIL_TEMPLATE_ID",
        default="d-bb1b3bb30ce8460cbe6ed008701affb1",
    )
    ALERT_ASSIGNED_TO_USER = config(
        "ALERT_ASSIGNED_TO_USER_EMAIL_TEMPLATE_ID",
        default="d-58ec64ed781e4c359e18da7ad97ac750",
    )


logger = logging.getLogger(__name__)

# CONSTS
FROM_EMAIL = config("SENDGRID_FROM_EMAIL", default="platform@keephq.dev")
# API_KEY = config("SENDGRID_API_KEY", default=None)
CC = config("SENDGRID_CC", default="founders@keephq.dev")
KEEP_EMAILS_ENABLED = config("KEEP_EMAILS_ENABLED", default=False, cast=bool)


def send_email(
    to_email: str,
    template_id: EmailTemplates,
    **kwargs,
) -> bool:
    if not KEEP_EMAILS_ENABLED:
        logger.debug("Emails are disabled, skipping sending email")
        return False

    logger.warning("Sending emails is disabled because SendGrid dependency was removed.")
    return False
