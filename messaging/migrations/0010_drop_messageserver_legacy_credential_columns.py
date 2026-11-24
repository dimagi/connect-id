from django.db import migrations


class Migration(migrations.Migration):
    """Drop the MessageServer.server_id and secret_key columns.

    Migration 0009 removed the fields from Django's state but kept the columns, so containers still on
    the release before it kept working during that deploy. Django no longer knows about the fields, so
    the columns are dropped with SQL. Their indexes go with them. Reversing restores them as 0009 left
    them: nullable, with server_id unique.
    """

    dependencies = [
        ("messaging", "0009_untrack_messageserver_legacy_credentials"),
    ]

    operations = [
        migrations.RunSQL(
            sql="ALTER TABLE messaging_messageserver DROP COLUMN server_id, DROP COLUMN secret_key;",
            reverse_sql=[
                "ALTER TABLE messaging_messageserver"
                " ADD COLUMN server_id varchar(100) NULL"
                " CONSTRAINT messaging_messageserver_server_id_key UNIQUE,"
                " ADD COLUMN secret_key varchar(255) NULL;",
                "CREATE INDEX messaging_messageserver_server_id_16435c01_like"
                " ON messaging_messageserver (server_id varchar_pattern_ops);",
            ],
        ),
    ]
