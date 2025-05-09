from django.conf import settings
from openai import OpenAI


class OpenAIService:
    AI_MODEL = "gpt-4o-mini"

    def __init__(self):
        self.client = OpenAI(
            api_key=settings.OPENAI_API_KEY,
        )

    def get_name_similarity_in_country(self, name: str, target_name: str, country_code: str) -> float:
        query = f"""
        Is '{name}' likely the same person as '{target_name}' in the country with country code '{country_code}'?
        Provide only the integer confidence score and nothing else.
        """
        response = self._get_response(query)
        try:
            return float(response)
        except ValueError:
            return 0.0

    def _get_response(self, query) -> str:
        instructions = """
        You're a helpful assistant that answers questions. If needed, do a web search.
        """

        response = self.client.responses.create(
            model=self.AI_MODEL,
            instructions=instructions,
            input=query,
        )
        return response.output_text
