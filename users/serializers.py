from rest_framework import serializers

from .models import Credential


class CredentialSerializer(serializers.ModelSerializer):
    opp_id = serializers.CharField(source="opportunity_id", read_only=True)
    date = serializers.SerializerMethodField()
    issuer = serializers.CharField(source="issuer.issuing_authority")
    issuer_environment = serializers.CharField(source="issuer.issuer_environment")

    def get_date(self, obj):
        return obj.created_at.isoformat()

    class Meta:
        model = Credential
        fields = [
            "uuid",
            "app_id",
            "opp_id",
            "date",
            "title",
            "issuer",
            "issuer_environment",
            "level",
            "type",
            "slug",
        ]
