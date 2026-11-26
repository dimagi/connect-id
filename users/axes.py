from axes.handlers.database import AxesDatabaseHandler


class AdminOnlyAxesHandler(AxesDatabaseHandler):
    """Axes lockout for the Django admin login only.

    ``AXES_ONLY_ADMIN_SITE`` only skips the lockout check outside the admin. Axes would still record every failed
    API login (the OAuth password grant and Basic auth on each request) and count it towards a username's lockout.
    The app's passwords are server-generated secrets that can't be guessed, and the API has its own throttles, so
    this handler ignores non-admin requests altogether.
    """

    def user_login_failed(self, sender, credentials: dict, request=None, **kwargs):
        if self.is_admin_request(request):
            super().user_login_failed(sender, credentials, request, **kwargs)

    def user_logged_in(self, sender, request, user, **kwargs):
        if self.is_admin_request(request):
            super().user_logged_in(sender, request, user, **kwargs)

    def user_logged_out(self, sender, request, user, **kwargs):
        if self.is_admin_request(request):
            super().user_logged_out(sender, request, user, **kwargs)
