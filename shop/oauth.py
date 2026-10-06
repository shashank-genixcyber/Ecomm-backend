"""Keep allauth's OAuth flow and explicitly verify every ID token signature."""
import jwt
from django.http import Http404
from allauth.account.internal.decorators import login_not_required
from allauth.socialaccount.internal import jwtkit
from allauth.socialaccount.providers.oauth2.client import OAuth2Error
from allauth.socialaccount.providers.oauth2.views import OAuth2CallbackView
from allauth.socialaccount.providers.openid_connect.views import OpenIDConnectOAuth2Adapter


class VerifiedOIDCAdapter(OpenIDConnectOAuth2Adapter):
    def _decode_id_token(self, app, id_token):
        try:
            if jwt.get_unverified_header(id_token).get("alg") not in {"RS256", "ES256"}:
                raise OAuth2Error("Unsupported ID token algorithm")
        except jwt.PyJWTError as error:
            raise OAuth2Error("Invalid ID token") from error
        data = jwtkit.verify_and_decode(
            credential=id_token, keys_url=self.openid_config["jwks_uri"],
            issuer=self.openid_config["issuer"], audience=app.client_id,
            lookup_kid=jwtkit.lookup_kid_jwk, verify_signature=True,
        )
        if not all(key in data for key in ("iss", "aud", "exp", "iat", "sub")) or not isinstance(data["sub"], str) or not data["sub"]:
            raise OAuth2Error("Missing ID token claims")
        return data


@login_not_required
def callback(request, provider_id):
    if provider_id != "shop":
        raise Http404
    return OAuth2CallbackView.adapter_view(VerifiedOIDCAdapter(request, provider_id))(request)

