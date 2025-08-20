import requests
import sentry_sdk
from django.conf import settings

OCS_CONFIG = settings.OCS_CONFIG


class OpenChatStudio:
    def check_name_similarity(self, reference_name: str, candidate_name: str, cultural_context: str) -> bool:
        message = (
            f"Reference Name: {reference_name}\nCandidate Name: {candidate_name}\nCultural Context: {cultural_context}"
        )
        data = {"messages": [self._get_user_message(message)]}
        bot_id = OCS_CONFIG["bots"]["cultural_name_similarity"]

        similarity_verdict = self.prompt_bot(data, bot_id=bot_id)
        if not similarity_verdict:
            return None
        return similarity_verdict.strip().upper() == "MATCH"

    def _get_user_message(self, content: str) -> dict:
        return {"role": "user", "content": content}

    def prompt_bot(self, data: dict, bot_id: str) -> dict:
        if not bot_id:
            return

        try:
            response = self._post_request(
                url=f"{OCS_CONFIG['api_base_url']}/openai/{bot_id}/chat/completions",
                data=data,
            )
        except Exception as e:
            sentry_sdk.capture_exception(e)
            return

        return self._extract_bot_message(response)

    def _extract_bot_message(self, response: dict) -> str:
        if not response.get("choices"):
            return None
        return response.get("choices", [{}])[0].get("message", {}).get("content")

    def _post_request(self, url: str, data: dict) -> dict:
        response = requests.post(url, headers=self._headers(), json=data)
        response.raise_for_status()
        return response.json()

    def _headers(self):
        return {"Content-Type": "application/json", "Authorization": f"Bearer {OCS_CONFIG['api_key']}"}
