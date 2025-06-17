import uuid
from unittest.mock import patch

from services.ai.ocs import OpenChatStudio


def request_reponse(response_message: str = None):
    return {
        "id": uuid.uuid4().hex,
        "choices": [
            {"finish_reason": "stop", "index": 0, "message": {"role": "assistant", "content": response_message}}
        ],
        "created": "",
        "model": None,
        "object": "chat.completion",
    }


class TestOCS:
    def test_get_user_message(self):
        content = "Hello, World!"
        message = OpenChatStudio()._get_user_message(content)
        assert message == {"role": "user", "content": content}

    def test_prompt_bot_no_bot_id(self):
        assert OpenChatStudio().prompt_bot(data={}, bot_id=None) is None

    @patch.object(OpenChatStudio, "_post_request")
    def test_prompt_bot_response(self, post_request_mock):
        post_request_mock.return_value = request_reponse(response_message="Hello, Bot!")
        response = OpenChatStudio().prompt_bot(data={}, bot_id="test_bot")
        assert response == "Hello, Bot!"

    def test_extract_bot_invalid_response(self):
        assert OpenChatStudio()._extract_bot_message({"choices": []}) is None


class TestOCSNameSimilarity:
    @patch.object(OpenChatStudio, "_post_request")
    def test_name_similarity_bot_message(self, post_request_mock, settings):
        settings.OCS_CONFIG["bots"]["cultural_name_similarity"] = "test_bot_id"
        post_request_mock.return_value = request_reponse(response_message="Match")

        OpenChatStudio().check_name_similarity(
            reference_name="John Doe", candidate_name="John Smith", cultural_context="Narnia"
        )
        post_request_mock.assert_called_once()
        _, kwargs = post_request_mock.call_args

        expected_message = "Reference Name: John Doe\nCandidate Name: John Smith\nCultural Context: Narnia"
        assert kwargs["data"]["messages"][0]["content"] == expected_message

    @patch.object(OpenChatStudio, "_post_request")
    def test_name_similarity_match(self, post_request_mock, settings):
        settings.OCS_CONFIG["bots"]["cultural_name_similarity"] = "test_bot_id"
        post_request_mock.return_value = request_reponse(response_message="Match")

        is_similar = OpenChatStudio().check_name_similarity(
            reference_name="John Doe", candidate_name="John Smith", cultural_context="Narnia"
        )
        assert is_similar

    @patch.object(OpenChatStudio, "_post_request")
    def test_name_similarity_mismatch(self, post_request_mock):
        post_request_mock.return_value = request_reponse(response_message="mismatch")

        is_similar = OpenChatStudio().check_name_similarity(
            reference_name="John Doe", candidate_name="John Smith", cultural_context="Narnia"
        )
        assert not is_similar

    @patch.object(OpenChatStudio, "_post_request")
    def test_name_similarity_no_response(self, post_request_mock):
        post_request_mock.return_value = request_reponse(response_message="")

        is_similar = OpenChatStudio().check_name_similarity(
            reference_name="John Doe", candidate_name="John Smith", cultural_context="Narnia"
        )
        assert not is_similar
