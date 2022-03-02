import hashlib
import json
import logging
import os
import re
from typing import Dict, Optional

import firebase_admin
import functions_framework
import google.cloud.logging
import requests as requests
from discord import Webhook, RequestsWebhookAdapter
from firebase_admin import credentials, firestore
from flask import Request, Response, abort, make_response
from google.cloud.firestore import Client
from google.cloud.firestore_v1.base_document import DocumentSnapshot
from google.cloud.functions.context import Context

URLS_COLLECTION = 'urls'

URL_DOC_URL_FIELD = 'url'
URL_DOC_VERDICT_FIELD = 'verdict'
URL_DOC_DEPARTMENT_FIELD = 'department'
URL_DOC_RESPONSE_FIELD = 'response'

URL_VERDICT_FAKE = 'FAKE'
URL_VERDICT_TRUSTABLE = 'TRUSTWORTHY'


WAITING_LIST_COLLECTION = 'waitinglist'

WAITING_LIST_WAITING_FOR_FIELD = "waiting_for"
WAITING_LIST_WAITING_USER_FIELD = "waiting_user"


def init_firestore_client() -> Optional[Client]:
    if not firebase_admin._apps:
        project_name = os.environ.get('GCP_PROJECT_NAME', None)
        if not project_name:
            abort(500, "Unknown project")
            return None

        creds = credentials.ApplicationDefault()
        firebase_admin.initialize_app(creds, {'projectId': project_name})
    return firestore.client()


def check_for_url(text: str) -> bool:
    URL_REGEX = 'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    url_pattern = re.compile(URL_REGEX)

    return re.fullmatch(url_pattern, text) is not None


def encode_to_id(url: str) -> str:
    return hashlib.sha256(url.encode('utf-8')).hexdigest()


def reply_for_existing_document(receiver_id: str, url_doc: DocumentSnapshot) -> None:
    response = url_doc.get(URL_DOC_RESPONSE_FIELD)
    send_messenger_message(receiver_id, response)


def send_messenger_message(receiver_id: str, message: str) -> None:
    """
    Send a message to a facebook user through the facebook Graph API
    :param receiver_id:
    :param message:
    :return:
    """

    page_access_token = os.environ.get('PAGE_ACCESS_TOKEN', None)
    if not page_access_token:
        return abort(500, 'The page access token is not available')

    payload = {
        'recipient': {'id': receiver_id},
        'message': {"text": message},
        'messaging_type': 'RESPONSE'
    }
    headers = {'content-type': 'application/json'}

    url = 'https://graph.facebook.com/v13.0/me/messages?access_token={}'.format(page_access_token)
    requests.post(url, json=payload, headers=headers)


def send_verification_request_on_discord(url_id):
    discord_webhook_url = os.environ.get('DISCORD_WEBHOOK', None)

    if not discord_webhook_url:
        logging.warning("Discord environment variables were not properly set")
        return

    webhook = Webhook.from_url(discord_webhook_url, adapter=RequestsWebhookAdapter())
    webhook.send(f'https://app.appsmith.com/applications/621b4b39445a8d746a06091f/pages/621b4b39445a8d746a060922'
                 f'?urlId={url_id}')


def handle_message(sender_id: str, received_message: Dict) -> None:
    """
    This method defines what happens when a user sends a message
    :param sender_id:
    :param received_message:
    :return:
    """

    if 'text' not in received_message:
        return
    text_message = received_message['text']
    if not check_for_url(text_message):
        # we only care about messages containing urls
        return

    db = init_firestore_client()

    url_id = encode_to_id(text_message)

    url_doc = db.collection(URLS_COLLECTION).document(url_id).get()
    if url_doc.exists and URL_DOC_RESPONSE_FIELD in url_doc.to_dict():
        return reply_for_existing_document(sender_id, url_doc)

    if not url_doc.exists:
        db.collection(URLS_COLLECTION).document(url_id).set({
            URL_DOC_URL_FIELD: text_message,
        })

        send_verification_request_on_discord(url_id)

    waiting_list_identifier = url_id + "$" + sender_id
    db.collection(WAITING_LIST_COLLECTION).document(encode_to_id(waiting_list_identifier)).set({
        WAITING_LIST_WAITING_FOR_FIELD: url_doc.reference,
        WAITING_LIST_WAITING_USER_FIELD: sender_id
    })

    send_messenger_message(sender_id, 'Mulţumim pentru informaţii, vom reveni în cel mai scurt timp cu o analiză.')


def handle_get_request(request: Request) -> Response:
    """
    Used as webhook to establish the connection between facebook and the function
    :param request:
    :return:
    """

    expected_verify_token = os.environ.get('VERIFY_TOKEN', None)
    if not expected_verify_token:
        logging.error("Verification token not available")
        return abort(500, "The verification token is not available")

    if 'hub.mode' not in request.args or 'hub.verify_token' not in request.args:
        logging.error("Invalid request, fields not present")
        return abort(403, 'Invalid request')

    mode = request.args.get('hub.mode')
    token = request.args.get('hub.verify_token')

    if mode != 'subscribe' or token != expected_verify_token:
        logging.error("Received unexpected values for fields")
        return abort(403, 'Invalid request')

    challenge = request.args.get('hub.challenge')
    logging.info("Successfully connected!")
    return make_response(challenge, 200)


def handle_post_request(request: Request) -> Response:
    data = request.data
    body = json.loads(data.decode('utf-8'))

    if 'object' in body and body['object'] == 'page':
        entries = body['entry']
        for entry in entries:
            event = entry['messaging'][0]
            print(event)

            sender_id = event['sender']['id']
            print('Sender PSID: {}'.format(sender_id))

            if 'message' in event:
                handle_message(sender_id, event['message'])

            return make_response('EVENT_RECEIVED', 200)
    else:
        return make_response('ERROR', 404)


@functions_framework.http
def handle_facebook_messenger_bot(request: Request) -> Response:
    """
    Entry method defining the cloud functions.

    This delegates the logic to other functions,
    each implementing the response for a specific HTTP method
    :param request:
    :return:
    """
    client = google.cloud.logging.Client()
    client.setup_logging()

    if request.method == "GET":
        return handle_get_request(request)
    elif request.method == "POST":
        response = handle_post_request(request)
        logging.info(response)
        return response
    else:
        return abort(405)


def retrieve_string_from_trigger_data(data: Dict, field: str) -> Optional[str]:
    if field not in data['value']['fields']:
        return None

    return data['value']['fields'][field]['stringValue']


def send_new_response_to_waiting_users(data: Dict, context: Context):
    client = google.cloud.logging.Client()
    client.setup_logging()

    verdict = retrieve_string_from_trigger_data(data, URL_DOC_VERDICT_FIELD)
    logging.info(f'Verdict: {verdict}')
    if not verdict or verdict == 'UNRESOLVED':
        return

    verdict_message = {URL_VERDICT_FAKE: 'sursă de dezinformare', URL_VERDICT_TRUSTABLE: 'sursă de încredere'}
    db = init_firestore_client()
    url_doc = db.collection(URLS_COLLECTION).document(context.resource.split('/')[-1]).get()
    logging.info(url_doc)
    waiting_list = db.collection(WAITING_LIST_COLLECTION).where(WAITING_LIST_WAITING_FOR_FIELD, '==', url_doc.reference)\
        .stream()

    url = retrieve_string_from_trigger_data(data, URL_DOC_URL_FIELD)
    response = retrieve_string_from_trigger_data(data, URL_DOC_RESPONSE_FIELD)
    for waiting_user in waiting_list:
        receiver = waiting_user.get(WAITING_LIST_WAITING_USER_FIELD)
        message = f"În legătură cu link-ul transmis: {url}\n\n" \
                  f"Verdictul scurt: {verdict_message[verdict]}\n\n" \
                  f"Răspuns detaliat:\n{response}"
        logging.info(f'Sending message to {receiver}')
        send_messenger_message(receiver, message)
