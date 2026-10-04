//! `clientDataJSON` as the WebAuthn client writes it, checked against the statement and the RP.

use serde_json::Value;

use super::credential::RpId;
use super::refusal::Refusal;
use super::statement::Statement;

/// `want` is `webauthn.get` for an assertion and `webauthn.create` for a registration: the same bytes
/// signed under the other type are refused, so a registration response cannot answer a presence request.
///
/// The client may add fields this host does not read (`tokenBinding`, a forward-compatibility marker), so
/// unknown fields are not refused; a field this host reads must have its spec type. `topOrigin` only exists
/// for a cross-origin ceremony, which this deployment never permits, so its presence is refused like
/// `crossOrigin: true`.
pub(super) fn check(
    client_data_json: &[u8],
    want: &'static str,
    statement: &Statement,
    rp_id: &RpId,
) -> Result<(), Refusal> {
    let data: Value =
        serde_json::from_slice(client_data_json).map_err(|_| Refusal::ClientDataMalformed)?;
    let text = |field: &str| data.get(field).and_then(Value::as_str);
    let kind = text("type").ok_or(Refusal::ClientDataMalformed)?;
    if kind != want {
        return Err(Refusal::ClientDataType {
            got: kind.to_string(),
            want,
        });
    }
    if text("challenge").ok_or(Refusal::ClientDataMalformed)?
        != statement.challenge().to_base64url()
    {
        return Err(Refusal::ChallengeMismatch);
    }
    let origin = text("origin").ok_or(Refusal::ClientDataMalformed)?;
    if origin != rp_id.origin() {
        return Err(Refusal::OriginMismatch {
            got: origin.to_string(),
        });
    }
    if data.get("topOrigin").is_some() {
        return Err(Refusal::CrossOrigin);
    }
    match data.get("crossOrigin") {
        None | Some(Value::Bool(false)) => Ok(()),
        Some(Value::Bool(true)) => Err(Refusal::CrossOrigin),
        Some(
            Value::Null | Value::Number(_) | Value::String(_) | Value::Array(_) | Value::Object(_),
        ) => Err(Refusal::ClientDataMalformed),
    }
}
