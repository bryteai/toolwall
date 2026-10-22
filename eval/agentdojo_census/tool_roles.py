"""Hand-labelled roles for AgentDojo v1.2.2 tools (labelled from tool names, parameters and docstrings).

SIDE_EFFECT[(suite, tool)] = {param: role}
  role 'authority' : decides WHO/WHERE the effect lands or WHICH object is changed
                     (recipient, IBAN, email address, participants, URL, channel, user, object id, booking target, credential)
  role 'content'   : what is written/sent (body, subject, title, amount, dates, text)
Any tool not listed is read-only. get_webpage is treated as an egress side effect (the URL leaves the system).
get_unread_emails changes state (marks e-mails read) but has no authority parameter.
"""
A, C = "authority", "content"
SIDE_EFFECT = {
    ("workspace", "send_email"): {"recipients": A, "cc": A, "bcc": A, "attachments": A, "subject": C, "body": C},
    ("workspace", "delete_email"): {"email_id": A},
    ("workspace", "create_calendar_event"): {"participants": A, "title": C, "start_time": C, "end_time": C, "description": C, "location": C},
    ("workspace", "cancel_calendar_event"): {"event_id": A},
    ("workspace", "reschedule_calendar_event"): {"event_id": A, "new_start_time": C, "new_end_time": C},
    ("workspace", "add_calendar_event_participants"): {"event_id": A, "participants": A},
    ("workspace", "append_to_file"): {"file_id": A, "content": C},
    ("workspace", "create_file"): {"filename": C, "content": C},
    ("workspace", "delete_file"): {"file_id": A},
    ("workspace", "share_file"): {"file_id": A, "email": A, "permission": A},   # permission is an ACL grant
    ("workspace", "get_unread_emails"): {},   # marks the returned e-mails as read: a state change with no target
    ("travel", "create_calendar_event"): {"participants": A, "title": C, "start_time": C, "end_time": C, "description": C, "location": C},
    ("travel", "cancel_calendar_event"): {"event_id": A},
    ("travel", "reserve_hotel"): {"hotel": A, "start_day": C, "end_day": C},
    ("travel", "reserve_car_rental"): {"company": A, "start_time": C, "end_time": C},
    ("travel", "reserve_restaurant"): {"restaurant": A, "start_time": C},
    ("travel", "send_email"): {"recipients": A, "cc": A, "bcc": A, "attachments": A, "subject": C, "body": C},
    ("banking", "send_money"): {"recipient": A, "amount": C, "subject": C, "date": C},
    ("banking", "schedule_transaction"): {"recipient": A, "amount": C, "subject": C, "date": C, "recurring": C},
    ("banking", "update_scheduled_transaction"): {"id": A, "recipient": A, "amount": C, "subject": C, "date": C, "recurring": C},
    ("banking", "update_password"): {"password": A},
    ("banking", "update_user_info"): {"first_name": C, "last_name": C, "street": C, "city": C},
    ("slack", "add_user_to_channel"): {"user": A, "channel": A},
    ("slack", "send_direct_message"): {"recipient": A, "body": C},
    ("slack", "send_channel_message"): {"channel": A, "body": C},
    ("slack", "invite_user_to_slack"): {"user": A, "user_email": A},
    ("slack", "remove_user_from_slack"): {"user": A},
    ("slack", "get_webpage"): {"url": A},
    ("slack", "post_webpage"): {"url": A, "content": C},
}
