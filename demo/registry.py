from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Consumer:
    id: str
    credential_type: str
    credential_name: str
    trigger: str
    operation: str

    @property
    def name(self):
        return self.id.replace("-", " ").title()

    @property
    def api_path(self):
        return f"/api/demo/services/{self.id}/run/"

    def public(self):
        return {**asdict(self), "name": self.name, "api_path": self.api_path, "asset_role": "business",
                **issuance_source(self)}


CONSUMERS = (
    Consumer("catalog-secret", "secret", "catalog-api-secret", "products", "authenticate"),
    Consumer("catalog-mtls", "certificate", "catalog-client-cert", "products", "tls_handshake"),
    Consumer("catalog-signing", "key", "catalog-signing-key", "products", "sign_verify"),
    Consumer("inventory-secret", "secret", "inventory-api-secret", "cart", "authenticate"),
    Consumer("pricing-mtls", "certificate", "pricing-client-cert", "cart", "tls_handshake"),
    Consumer("promotions-oauth", "oauth_token", "promotions-access-token", "cart", "authorize"),
    Consumer("checkout-secret", "secret", "checkout-api-secret", "checkout", "authenticate"),
    Consumer("order-signing", "key", "order-signing-key", "checkout", "sign_verify"),
    Consumer("fulfillment-oauth", "oauth_token", "fulfillment-access-token", "checkout", "authorize"),
    Consumer("tracking-mtls", "certificate", "tracking-client-cert", "orders", "tls_handshake"),
    Consumer("receipt-signing", "key", "receipt-signing-key", "orders", "sign_verify"),
    Consumer("notifications-oauth", "oauth_token", "notifications-access-token", "orders", "authorize"),
)
BY_ID = {consumer.id: consumer for consumer in CONSUMERS}
CREDENTIAL_TYPES = ("secret", "certificate", "key", "oauth_token")


def issuance_source(consumer):
    if consumer.credential_type == "oauth_token":
        label, kind = "Google OAuth", "cloud_broker"
    elif consumer.id in {"inventory-secret", "pricing-mtls", "order-signing"}:
        label, kind = "PostgreSQL DB", "database"
    else:
        label, kind = "Azure Vault", "vault"
    return {"issuance_source": label, "issuance_source_type": kind, "source_simulated": True}


def oauth_scope(consumer):
    return f"{consumer.id.removesuffix('-oauth')}:read"


def oauth_audience(consumer):
    return f"urn:everyday:demo:{consumer.id}"
