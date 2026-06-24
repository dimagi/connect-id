from rest_framework import serializers

from .models import UserCredential


class UserCredentialSerializer(serializers.ModelSerializer):
    uuid = serializers.UUIDField(source="credential.uuid", read_only=True)
    app_id = serializers.CharField(source="credential.app_id", read_only=True)
    opp_id = serializers.CharField(source="credential.opportunity_id", read_only=True)
    date = serializers.SerializerMethodField()
    title = serializers.CharField(source="credential.title", read_only=True)
    issuer = serializers.CharField(source="credential.issuer.issuing_authority", read_only=True)
    issuer_environment = serializers.CharField(source="credential.issuer.issuer_environment", read_only=True)
    level = serializers.CharField(source="credential.level", read_only=True)
    type = serializers.CharField(source="credential.type", read_only=True)
    slug = serializers.CharField(source="credential.slug", read_only=True)

    def get_date(self, obj):
        return obj.created_at.isoformat()

    class Meta:
        model = UserCredential
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
