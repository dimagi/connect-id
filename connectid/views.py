from django.http import HttpResponse, JsonResponse


def assetlinks_json(request):
    assetfile = [
        {
            "relation": ["delegate_permission/common.handle_all_urls"],
            "target": {
                "namespace": "android_app",
                "package_name": "org.commcare.dalvik",
                "sha256_cert_fingerprints":
                [
                    "88:57:18:F8:E8:7D:74:04:97:AE:83:65:74:ED:EF:10:40:D9:4C:E2:54:F0:E0:40:64:77:96:7F:D1:39:F9:81",
                    "89:55:DF:D8:0E:66:63:06:D2:6D:88:A4:A3:88:A4:D9:16:5A:C4:1A:7E:E1:C6:78:87:00:37:55:93:03:7B:03"
                ]
            }
        },
        {
            "relation": ["delegate_permission/common.handle_all_urls"],
            "target": {
                "namespace": "android_app",
                "package_name": "org.commcare.dalvik.debug",
                "sha256_cert_fingerprints":
                [
                    "88:57:18:F8:E8:7D:74:04:97:AE:83:65:74:ED:EF:10:40:D9:4C:E2:54:F0:E0:40:64:77:96:7F:D1:39:F9:81"
                ]
            }
        },
    ]
    return JsonResponse(assetfile, safe=False)


def deeplink(request, subpath):
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="refresh" content="5;url=https://play.google.com/store/apps/details?id=org.commcare.dalvik&hl=en_IN&pli=1">
        <title>Redirecting to CommCare</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 600px;
                margin: 50px auto;
                padding: 20px;
                text-align: center;
                line-height: 1.6;
            }
            .message {
                margin-bottom: 20px;
            }
            .link {
                color: #007bff;
                text-decoration: none;
            }
            .link:hover {
                text-decoration: underline;
            }
        </style>
    </head>
    <body>
        <div class="message">
            You are being redirected to install CommCare app, please install CommCare and re-open this link
        </div>
        <a href="https://play.google.com/store/apps/details?id=org.commcare.dalvik&hl=en_IN&pli=1" class="link">
            Click here if you are not redirected automatically
        </a>
    </body>
    </html>
    """
    return HttpResponse(html_content)