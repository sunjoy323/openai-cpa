import os
import re
import time
from utils.gmail_oauth_handler import GmailOAuthHandler
from utils import config as cfg

def get_gmail_otp_via_oauth(target_email, proxy=None):
    config_dir = os.path.dirname(cfg.CONFIG_PATH)
    client_secrets = os.path.join(config_dir, "credentials.json")
    token_path = os.path.join(config_dir, "token.json")

    handler = GmailOAuthHandler()
    service = handler.get_service(client_secrets, token_path, proxy=proxy)

    if not service:
        return None
    emails = handler.fetch_and_mark_read(service, target_email, search_query="is:unread")
    if not emails:
        return None
    for mail in emails:
        code_match = re.search(r'\b\d{6}\b', mail['body'])
        if code_match:
            otp_code = code_match.group()
            return otp_code

    return None