# Performance Analysis Report for Connect-ID

This document outlines identified performance issues in the Connect-ID codebase, organized by severity (High/Medium/Low) with actionable recommendations for each issue.

## Table of Contents
1. [High Priority Issues](#high-priority-issues)
2. [Medium Priority Issues](#medium-priority-issues)
3. [Low Priority Issues](#low-priority-issues)
4. [Summary and Recommendations](#summary-and-recommendations)

---

## High Priority Issues

### 1. N+1 Query Problem in `send_bulk_notification()`
**Location:** `utils/notification.py` (lines 10-55)

**Problem:**
For each user in the notification list, the code performs a separate database query to fetch the FCMDevice:
```python
for user in users:
    notification.save()  # One INSERT per user
    fcm_device = FCMDevice.objects.filter(user=user, active=True).first()  # One SELECT per user
```

**Impact:** For bulk notifications to N users, this results in N+1 database queries instead of 2 optimized queries.

**Recommendation:**
```python
from django.db.models import Prefetch

def send_bulk_notification(message: NotificationData):
    # ...
    # Prefetch FCM devices to avoid N+1 queries
    users = ConnectUser.objects.filter(
        username__in=message.usernames, is_active=True
    ).prefetch_related(
        Prefetch('fcmdevice_set', queryset=FCMDevice.objects.filter(active=True), to_attr='active_devices')
    )
    
    # Process users with prefetched devices
    for user in users:
        notification = Notification(
            user=user,
            json={"title": message.title, "body": message.body, "data": message.data}
        )
        notification.save()
        
        # Access prefetched devices - no additional query
        fcm_device = user.active_devices[0] if user.active_devices else None
        # ... rest of the logic
```

**Note:** For even better performance with large user counts, consider using `bulk_create` with the `update_conflicts` parameter (Django 4.1+) to handle the notification creation, but ensure proper ID handling for subsequent FCM operations.


---

### 2. N+1 Query Problem in `RetrieveMessageView`
**Location:** `messaging/views.py` (lines 259-293)

**Problem:**
Despite using `prefetch_related`, the code still performs additional queries inside the loop:
```python
for channel in channels:
    # ...
    channel_messages = Message.objects.filter(  # Separate query for each channel!
        channel=channel, direction=MessageDirection.MOBILE, status=MessageStatus.PENDING
    )
```

**Impact:** For N channels, this results in N additional database queries.

**Recommendation:**
Use a single query to fetch all pending messages, then group them in Python:
```python
def get(self, request, *args, **kwargs):
    user = request.user
    channels = Channel.objects.filter(connect_user=user).select_related("server")
    
    # Fetch ALL pending messages for the user's channels in one query
    pending_messages = Message.objects.filter(
        channel__connect_user=request.user,
        direction=MessageDirection.MOBILE,
        status=MessageStatus.PENDING
    ).select_related("channel")
    
    channels_data = [
        {
            "channel_source": channel.visible_name,
            "channel_id": str(channel.channel_id),
            "key_url": channel.server.key_url,
            "consent": channel.user_consent,
        }
        for channel in channels
    ]
    
    messages_data = MessageSerializer(pending_messages, many=True).data
    return JsonResponse({"channels": channels_data, "messages": messages_data})
```

---

### 3. N+1 Query Problem in `RetrieveNotificationView`
**Location:** `messaging/views.py` (lines 368-397)

**Problem:**
The loop accesses `channel.server.key_url` for each channel without proper prefetching:
```python
for channel in user_channels:
    channels_data.append({
        "key_url": channel.server.key_url,  # Triggers a query for each channel
    })
```

**Recommendation:**
```python
user_channels = Channel.objects.filter(connect_user=request.user).select_related("server")
```

---

### 4. Loop with External API Calls in `resend_notifications_for_undelivered_messages()`
**Location:** `messaging/task.py` (lines 82-99)

**Problem:**
Each undelivered message triggers a separate `send_bulk_notification()` call, which in turn makes individual FCM API calls. For many undelivered messages, this is extremely slow.

**Impact:** If there are 1000 undelivered messages, this could result in 1000+ external API calls executed sequentially.

**Recommendation:**
1. Batch messages by user and send one notification per user
2. Consider using Firebase's batch messaging API for multiple recipients:
```python
@shared_task(name="resend_notifications_for_undelivered_messages")
def resend_notifications_for_undelivered_messages():
    undelivered_msgs = Message.objects.filter(
        received__isnull=True, 
        direction=MessageDirection.MOBILE
    ).select_related("channel", "channel__connect_user")
    
    # Group messages by user
    user_messages = defaultdict(list)
    for msg in undelivered_msgs:
        username = msg.channel.connect_user.username
        user_messages[username].append(msg)
    
    # Send one aggregated notification per user
    for username, messages in user_messages.items():
        # Send summary notification instead of individual ones
        message_to_send = NotificationData(
            usernames=[username], 
            data={"message_count": len(messages), "latest_message": MessageSerializer(messages[-1]).data}
        )
        try:
            send_bulk_notification(message_to_send)
        except Exception as e:
            sentry_sdk.capture_exception(e)
```

---

### 5. Synchronous External API Calls in View Handlers
**Location:** Multiple files

**Problem:**
Several synchronous external API calls block request processing:
- `utils/twilio.py`: `lookup_telecom_provider()` - Twilio API call
- `services/ai/ocs.py`: `prompt_bot()` - OpenChatStudio API call
- `utils/connect.py`: `check_number_for_existing_invites()` - External Connect API call

**Impact:** These block the request thread, reducing server throughput.

**Recommendation:**
Move external API calls to async tasks using Celery:
```python
# For non-critical operations like telecom lookup
@shared_task
def async_lookup_telecom_provider(phone_number, payment_profile_id):
    telecom_provider = lookup_telecom_provider(phone_number)
    PaymentProfile.objects.filter(id=payment_profile_id).update(telecom_provider=telecom_provider)
```

---

## Medium Priority Issues

### 6. Missing Database Indexes on Frequently Queried Fields
**Location:** Various model files

**Problem:**
Several fields used in `filter()` operations lack indexes:

| Model | Field | Used in |
|-------|-------|---------|
| `ConnectUser` | `phone_number` + `is_active` | Multiple views for user lookup |
| `ConfigurationSession` | `phone_number` | Phone number-based session lookup |
| `ConfigurationSession` | `expires` | Session validity checks |
| `Message` | `received` + `direction` | Undelivered message queries |
| `Notification` | `received` | Notification retrieval |
| `UserCredential` | `accepted` | Credential filtering |

**Recommendation:**
Add composite indexes:
```python
class ConnectUser(AbstractUser):
    class Meta:
        indexes = [
            models.Index(fields=['phone_number', 'is_active']),
        ]

class Message(models.Model):
    class Meta:
        indexes = [
            models.Index(fields=['received', 'direction', 'status']),
            models.Index(fields=['channel', 'direction', 'status']),
        ]

class Notification(models.Model):
    class Meta:
        indexes = [
            models.Index(fields=['user', 'received']),
        ]
```

---

### 7. Loop with Individual Database Operations in `AddCredential`
**Location:** `users/views.py` (lines 666-697)

**Problem:**
For each credential in the request, multiple database operations occur:
```python
for index, cred in enumerate(creds):
    credential, _ = Credential.objects.get_or_create(...)  # 1-2 queries
    credential.save()  # 1 query
    users = ConnectUser.objects.filter(...)  # 1 query
    for user in users:
        UserCredential.add_credential(user, credential, request)  # Multiple queries + SMS per user
```

**Impact:** For 10 credentials with 100 users each, this could result in 1000+ database queries and SMS sends.

**Recommendation:**
1. Use bulk operations where possible
2. Queue SMS sends as async tasks
3. Consider batching the whole operation:
```python
def post(self, request, *args, **kwargs):
    # ... validation ...
    
    credentials_to_update = []
    user_credentials_to_create = []
    sms_tasks = []
    
    for cred in creds:
        # Collect credentials
        credential, created = Credential.objects.get_or_create(...)
        if needs_update:
            credentials_to_update.append(credential)
        
        # Collect user credentials
        users = ConnectUser.objects.filter(username__in=cred.get("usernames", []), is_active=True)
        for user in users:
            user_credentials_to_create.append(UserCredential(user=user, credential=credential))
    
    # Bulk update/create - use update_or_create pattern for proper error handling
    Credential.objects.bulk_update(credentials_to_update, ['title', 'app_id', 'opportunity_id'])
    
    # Filter out existing user credentials before bulk create to maintain proper tracking
    existing_pairs = set(
        UserCredential.objects.filter(
            user__in=[uc.user for uc in user_credentials_to_create],
            credential__in=[uc.credential for uc in user_credentials_to_create]
        ).values_list('user_id', 'credential_id')
    )
    new_user_credentials = [
        uc for uc in user_credentials_to_create 
        if (uc.user_id, uc.credential_id) not in existing_pairs
    ]
    created_credentials = UserCredential.objects.bulk_create(new_user_credentials)
    
    # Queue SMS sends only for newly created credentials
    if created_credentials:
        async_send_credential_sms.delay([uc.id for uc in created_credentials])
```

---

### 8. Inefficient Token Revocation in `confirm_deactivation`
**Location:** `users/views.py` (lines 807-830)

**Problem:**
Tokens are fetched and revoked individually:
```python
tokens = list(AccessToken.objects.filter(user=user)) + list(RefreshToken.objects.filter(user=user))
for token in tokens:
    token.revoke()
```

**Recommendation:**
Use bulk delete or update:
```python
# If revoke() just deletes the tokens:
AccessToken.objects.filter(user=user).delete()
RefreshToken.objects.filter(user=user).delete()

# If revoke() sets a flag:
AccessToken.objects.filter(user=user).update(revoked=timezone.now())
RefreshToken.objects.filter(user=user).update(revoked=timezone.now())
```

---

### 9. Geocoding in Request Handler
**Location:** `users/models.py` (lines 294-306)

**Problem:**
The `ConfigurationSession.country_code` property calls the Nominatim geocoding API synchronously during request processing:
```python
@property
def country_code(self):
    geolocator = Nominatim(user_agent="PersonalID")
    location = geolocator.reverse(f"{lat} {lon}", language="en")  # External API call!
```

**Impact:** Adds 100-500ms+ latency to every request that accesses this property.

**Recommendation:**
1. Cache the country code when the session is created
2. Make the geocoding async:
```python
class ConfigurationSession(models.Model):
    cached_country_code = models.CharField(max_length=10, blank=True, null=True)
    
    def save(self, *args, **kwargs):
        if self.gps_location and not self.cached_country_code:
            # Queue async geocoding task
            super().save(*args, **kwargs)
            geocode_session_country.delay(self.key)
        else:
            super().save(*args, **kwargs)
    
    @property
    def country_code(self):
        return self.cached_country_code

@shared_task
def geocode_session_country(session_key):
    session = ConfigurationSession.objects.get(key=session_key)
    coords = session.gps_location.split()
    geolocator = Nominatim(user_agent="PersonalID")
    location = geolocator.reverse(f"{coords[0]} {coords[1]}", language="en")
    country_code = location.raw.get("address", {}).get("country_code")
    session.cached_country_code = country_code
    session.save(update_fields=['cached_country_code'])
```

---

### 10. S3 Operations in Request Handler
**Location:** `users/services.py` (lines 19-52)

**Problem:**
Photo upload and retrieval from S3 are synchronous operations in the request path:
```python
def upload_photo_to_s3(image_base64, username):
    s3_client = boto3.client("s3")  # Creates a new client on each call
    s3_client.put_object(...)

def get_user_photo_base64(username):
    s3_client = boto3.client("s3")  # Creates a new client on each call
    objs = s3_client.list_objects_v2(...)
    response = s3_client.get_object(...)
```

**Recommendation:**
1. Reuse the S3 client (singleton pattern)
2. Consider async upload via Celery for non-blocking operations
3. Cache photo URLs or add CloudFront CDN:
```python
# Singleton S3 client
_s3_client = None

def get_s3_client():
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client("s3")
    return _s3_client

# For photo retrieval, consider pre-signed URLs instead of base64
def get_user_photo_url(username):
    s3_client = get_s3_client()
    # Generate pre-signed URL (faster, no data transfer through server)
    return s3_client.generate_presigned_url(
        'get_object',
        Params={'Bucket': settings.AWS_S3_PHOTO_BUCKET_NAME, 'Key': f"{username}.jpg"},
        ExpiresIn=3600
    )
```

---

## Low Priority Issues

### 11. Twilio Client Created on Every SMS Send
**Location:** `utils/__init__.py` (lines 6-8)

**Problem:**
A new Twilio client is created for every SMS send operation:
```python
def send_sms(to, body, sender=None):
    client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
```

**Recommendation:**
Use a singleton pattern:
```python
_twilio_client = None

def get_twilio_client():
    global _twilio_client
    if _twilio_client is None:
        _twilio_client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    return _twilio_client

def send_sms(to, body, sender=None):
    client = get_twilio_client()
    client.messages.create(...)
```

---

### 12. Sorting in Python Instead of Database
**Location:** `users/views.py` (lines 627-630)

**Problem:**
Demo users are sorted in Python after combining two querysets:
```python
demo_users = list(demo_phone_devices) + list(demo_connect_users)
sorted_demo_users = sorted(demo_users, key=lambda x: x["phone_number"])
```

**Recommendation:**
Use `UNION` or `order_by()` at the database level:
```python
from django.db.models import Value, CharField

demo_phone_devices = PhoneDevice.objects.filter(...).annotate(
    source=Value('device', output_field=CharField())
).values("phone_number", "token", "source")

demo_connect_users = ConnectUser.objects.filter(...).annotate(
    token=F("deactivation_token"),
    source=Value('user', output_field=CharField())
).values("phone_number", "token", "source")

# Union and order in database
demo_users = demo_phone_devices.union(demo_connect_users).order_by("phone_number")
```

---

### 13. Response Sorting in `send_bulk_notification`
**Location:** `utils/notification.py` (line 54)

**Problem:**
```python
message_result["responses"].sort(key=lambda r: message.usernames.index(r["username"]))
```
Using `list.index()` in a sort key is O(n²) complexity.

**Recommendation:**
Use a dictionary for O(n) lookup:
```python
username_order = {username: i for i, username in enumerate(message.usernames)}
# Use len(message.usernames) to place unknown usernames at the end in a predictable order
message_result["responses"].sort(key=lambda r: username_order.get(r["username"], len(message.usernames)))
```

---

### 14. Suboptimal `FetchUserCounts` Query
**Location:** `users/views.py` (lines 833-874)

**Problem:**
The `non_invited_users_qs` uses a complex subquery that could be slow with many sessions:
```python
session_exists = ConfigurationSession.objects.filter(
    phone_number=OuterRef("phone_number"),
    expires__gte=OuterRef("date_joined"),
    created__lte=OuterRef("date_joined"),
    invited_user=False,
)
```

**Recommendation:**
Consider adding an index on `ConfigurationSession`:
```python
class ConfigurationSession(models.Model):
    class Meta:
        indexes = [
            models.Index(fields=['phone_number', 'invited_user', 'created', 'expires']),
        ]
```

Or, if this query is called frequently, consider caching the results or maintaining a denormalized count.

---

## Summary and Recommendations

### Priority Action Items

| Priority | Issue | Estimated Impact | Effort |
|----------|-------|------------------|--------|
| High | N+1 in `send_bulk_notification` | 50-80% reduction in queries | Low |
| High | N+1 in `RetrieveMessageView` | Significant query reduction | Low |
| High | Batch undelivered message notifications | Reduce API calls by 90%+ | Medium |
| High | Async external API calls | Improve request latency | Medium |
| Medium | Add database indexes | Improve query performance | Low |
| Medium | Bulk operations in `AddCredential` | Reduce DB operations | Medium |
| Medium | Cache geocoding results | Remove external API from request path | Low |
| Medium | S3 client reuse | Reduce connection overhead | Low |

### Quick Wins (Low effort, high impact)
1. Add `select_related()` and `prefetch_related()` to existing queries
2. Add database indexes for frequently filtered fields
3. Implement singleton patterns for external service clients

### Medium-term Improvements
1. Move external API calls to Celery tasks
2. Implement bulk create/update operations
3. Cache geocoding and other expensive computations

### Long-term Recommendations
1. Consider adding Redis caching for frequently accessed data
2. Implement database query logging in development to catch new N+1 issues
3. Add performance tests to CI/CD pipeline
4. Consider read replicas if database load becomes an issue
