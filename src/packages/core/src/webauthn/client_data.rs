use serde::de::{Deserializer, Error as _, MapAccess, Visitor};
use serde::Deserialize;
use serde_json::Value;

use super::credential::RpId;
use super::refusal::Refusal;
use super::statement::Statement;

/// The members of the clientDataJSON object, each name once. Read through a visitor rather than a
/// `serde_json::Value` or a derived struct, because both read a signed frame more leniently than the spec's
/// one-object shape and a verifier must not:
///
/// ```text
/// Value          "challenge": 0, "challenge": "<good>"  -> keeps the last member
/// derived struct "crossOrigin": null                     -> reads a present null as an absent member
/// derived struct ["webauthn.get", "<good>", "<origin>"]  -> fills the fields from a positional array
/// ```
struct Members(Vec<(String, Value)>);

impl Members {
    fn get(&self, name: &str) -> Option<&Value> {
        self.0
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    }
}

impl<'de> Deserialize<'de> for Members {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Distinct;

        impl<'de> Visitor<'de> for Distinct {
            type Value = Members;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object whose member names are distinct")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Members, A::Error> {
                let mut members: Vec<(String, Value)> = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, Value>()? {
                    if members.iter().any(|(seen, _)| *seen == key) {
                        return Err(A::Error::custom(format!("duplicate member {key}")));
                    }
                    members.push((key, value));
                }
                Ok(Members(members))
            }
        }

        deserializer.deserialize_map(Distinct)
    }
}

/// `want` is `webauthn.get` for an assertion and `webauthn.create` for a registration, so a registration
/// response cannot answer a presence request.
///
/// ```text
/// unknown member (`tokenBinding`, a forward-compatibility marker) -> kept: the client may add them
/// a member this host reads, not its spec type                     -> ClientDataMalformed
/// `topOrigin` present at all                                      -> CrossOrigin: only a cross-origin
///                                                                    ceremony carries it
/// ```
pub(super) fn check(
    client_data_json: &[u8],
    want: &'static str,
    statement: &Statement,
    rp_id: &RpId,
) -> Result<(), Refusal> {
    let data: Members =
        serde_json::from_slice(client_data_json).map_err(|_| Refusal::ClientDataMalformed)?;
    let text = |member: &str| data.get(member).and_then(Value::as_str);
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
