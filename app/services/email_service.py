import requests


class MailgunEmailService:
    """MAILGUN email service"""

    def __init__(self, mailgun_api_key, mailgun_domain, mailgun_email):
        self.mailgun_api_key = mailgun_api_key
        self.mailgun_domain = mailgun_domain
        self.mailgun_email = mailgun_email

    async def send_email(self, to_emails, subject, message):
        """Sends an email using the Mailgun API."""

        to_emails = to_emails.split(",")
        url = f"https://api.mailgun.net/v3/{self.mailgun_domain}/messages"
        data = {
            "from": self.mailgun_email,  # Your verified email address on Mailgun
            "to": to_emails,
            "subject": subject,
            "text": message
        }
        try:
            response = requests.post(
                url,
                auth=("api", self.mailgun_api_key),
                data=data
            )
            print("RES: ", response.text)
            if response.status_code == 200:
                print(f"Email sent successfully to {to_emails} with status code: {response.status_code}\n-----------------------------------\n")
                return True, response.status_code
            return False, response.status_code
        except requests.exceptions.RequestException as e:
            print(f"Error sending email: {e}")
            return False, 400

