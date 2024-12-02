from twilio.rest import Client


class SmsService:

    def __init__(self, account_sid, auth_token, twilio_phone_number):
        self.account_sid = account_sid
        self.auth_token = auth_token
        self.twilio_phone_number = twilio_phone_number

    def send_sms(self, to_phones, message):
        """Sends an SMS using Twilio."""
        try:

            to_phones = to_phones.split(",")
            client = Client(self.account_sid, self.auth_token)
            for phone in to_phones:
                print(f"Sending SMS to {phone}")
                message = client.messages.create(
                    body=message,
                    from_=self.twilio_phone_number,
                    to=phone
                )
                print(f"SMS sent successfully to {phone}. Message SID: {message.sid}\n-----------------------------------\n")
            return True

        except Exception as e:
            print(f"Failed to send SMS: {e}")
            return False
