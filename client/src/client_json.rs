//! Check object-key uniqueness using Serde before decoding a transport response.
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use std::{collections::BTreeSet, fmt};

struct Unique;

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(Self)
    }
}

impl<'de> Visitor<'de> for Unique {
    type Value = Self;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON with unique object keys")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self, E> {
        Ok(self)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Self, E> {
        Ok(self)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Self, E> {
        Ok(self)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Self, E> {
        Ok(self)
    }
    fn visit_str<E>(self, _: &str) -> Result<Self, E> {
        Ok(self)
    }
    fn visit_unit<E>(self) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut array: A) -> Result<Self, A::Error> {
        while array.next_element::<Self>()?.is_some() {}
        Ok(self)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Self, A::Error> {
        let mut keys = BTreeSet::new();
        while let Some(key) = object.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate response key"));
            }
            object.next_value::<Self>()?;
        }
        Ok(self)
    }
}

pub(super) fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> crate::error::Result<T> {
    // This first pass retains no values. Both passes keep Serde's depth limit;
    // transport body limits apply before this decoder sees any bytes.
    serde_json::from_slice::<Unique>(body).map_err(|_| crate::error::Error::Reconcile)?;
    serde_json::from_slice(body).map_err(|_| crate::error::Error::Reconcile)
}

#[cfg(test)]
#[path = "../tests/unit/client_json.rs"]
mod tests;
