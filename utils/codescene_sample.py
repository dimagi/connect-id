"""Sample code to exercise CodeScene PR review. Not imported anywhere; do not merge.

Each function deliberately contains a code smell that CodeScene's code health checks should flag.
"""


# Smell: Excess Number of Function Arguments + Complex Conditional
def build_user_summary(first_name, last_name, phone, email, country, language, is_active, is_locked, age):
    if is_active and not is_locked and age >= 18 and country in ("IN", "KE", "NG") and language != "":
        status = "eligible"
    else:
        status = "ineligible"
    return {
        "name": f"{first_name} {last_name}",
        "phone": phone,
        "email": email,
        "country": country,
        "language": language,
        "status": status,
    }


# Smell: Complex Method + Deep, Nested Complexity + Bumpy Road
def classify_payment(payment):
    result = []
    if payment:
        if payment.get("amount") is not None:
            if payment["amount"] > 0:
                if payment.get("currency") == "USD":
                    if payment["amount"] > 1000:
                        result.append("large-usd")
                    elif payment["amount"] > 100:
                        result.append("medium-usd")
                    else:
                        result.append("small-usd")
                elif payment.get("currency") == "INR":
                    if payment["amount"] > 80000:
                        result.append("large-inr")
                    elif payment["amount"] > 8000:
                        result.append("medium-inr")
                    else:
                        result.append("small-inr")
                else:
                    result.append("unknown-currency")
            else:
                result.append("non-positive")
        else:
            result.append("missing-amount")

    for flag in payment.get("flags", []) if payment else []:
        if flag == "refund":
            if payment.get("refunded"):
                result.append("already-refunded")
            else:
                result.append("refund-pending")
        elif flag == "dispute":
            if payment.get("disputed_at"):
                result.append("disputed")
            else:
                result.append("dispute-unknown")

    for note in payment.get("notes", []) if payment else []:
        if note:
            if "fraud" in note.lower():
                result.append("fraud-note")
            elif "manual" in note.lower():
                result.append("manual-note")
    return result


# Smell: Code Duplication (the two functions below are near-identical)
def format_sms_message(user, template, opportunity):
    lines = []
    lines.append(f"Hello {user['first_name']} {user['last_name']},")
    lines.append(template.replace("{opportunity}", opportunity["name"]))
    if opportunity.get("deadline"):
        lines.append(f"Deadline: {opportunity['deadline']}")
    if opportunity.get("payment"):
        lines.append(f"Payment: {opportunity['payment']} {opportunity.get('currency', 'USD')}")
    lines.append("Reply STOP to unsubscribe.")
    return "\n".join(lines)


def format_push_message(user, template, opportunity):
    lines = []
    lines.append(f"Hello {user['first_name']} {user['last_name']},")
    lines.append(template.replace("{opportunity}", opportunity["name"]))
    if opportunity.get("deadline"):
        lines.append(f"Deadline: {opportunity['deadline']}")
    if opportunity.get("payment"):
        lines.append(f"Payment: {opportunity['payment']} {opportunity.get('currency', 'USD')}")
    lines.append("Open the app for details.")
    return "\n".join(lines)
