use bcder::decode::{DecodeError, IntoSource, Source};
use bcder::{decode, encode, Captured, Ia5String, Mode, Tag, Oid};
use bcder::encode::{PrimitiveContent, Values};
use crate::oid;
use crate::crypto::{Signer, SigningError};
use crate::repository::resources::{AsResourcesBuilder};
use super::error::{ValidationError};
use super::{Cert, ResourceCert};
use super::sigobj::{SignedObject, SignedObjectBuilder};
use crate::resources::Asn;
use crate::uri::Https;

#[derive(Clone, Debug)]
pub struct Pad {
    signed: SignedObject,
    content: PeeringApiDiscovery,
}

impl Pad {
    pub fn decode<S: IntoSource>(
        source: S,
        strict: bool
    ) -> Result<Self, DecodeError<<S::Source as Source>::Error>> {
        let signed = SignedObject::decode_if_type(
            source, &oid::PEERING_API_DISCOVERY, strict,
        )?;
        let content = signed.decode_content(|cons| {
            PeeringApiDiscovery::take_from(cons)
        }).map_err(DecodeError::convert)?;
        Ok(Pad { signed, content })
    }

    pub fn process<F>(
        self,
        issuer: &ResourceCert,
        strict: bool,
        check_crl: F
    ) -> Result<(ResourceCert, PeeringApiDiscovery), ValidationError>
    where F: FnOnce(&Cert) -> Result<(), ValidationError> {
        let cert = self.signed.validate(issuer, strict)?;
        check_crl(cert.as_ref())?;
        Ok((cert, self.content))
    }

    /// Returns a value encoder for a reference to a ROA.
    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        self.signed.encode_ref()
    }

    /// Returns a DER encoded Captured for this ROA.
    pub fn to_captured(&self) -> Captured {
        self.encode_ref().to_captured(Mode::Der)
    }

    /// Returns a reference to the EE certificate of this ROA.
    pub fn cert(&self) -> &Cert {
        self.signed.cert()
    }

    /// Returns a reference to the content of the ROA object
    pub fn content(&self) -> &PeeringApiDiscovery {
        &self.content
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Pad {
    fn serialize<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        let bytes = self.to_captured().into_bytes();
        let b64 = crate::util::base64::Serde.encode(&bytes);
        b64.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Pad {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        use serde::de;

        let s = String::deserialize(deserializer)?;
        let decoded = crate::util::base64::Serde.decode(&s).map_err(de::Error::custom)?;
        let bytes = bytes::Bytes::from(decoded);
        Pad::decode(bytes, true).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug)]
pub struct PeeringApiDiscovery {
    asn: Asn,
    peering_api_uri: Https
}

impl PeeringApiDiscovery {
    pub fn asn(&self) -> Asn {
        self.asn
    }

    pub fn peering_api_uri(&self) -> &Https {
        &self.peering_api_uri
    }
}

impl PeeringApiDiscovery {
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            // version [0] EXPLICIT INTEGER DEFAULT 0
            cons.take_opt_constructed_if(Tag::CTX_0, |c| c.skip_u8_if(0))?;
            let asn = Asn::take_from(cons)?;
            let uri = Ia5String::take_from(cons)?.into_bytes();
            let peering_api_uri = Https::from_bytes(uri)
                .map_err(|e| DecodeError::content(e.to_string(), Default::default()))?;
            Ok(PeeringApiDiscovery {
                asn,
                peering_api_uri
            })
        })
    }

    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        encode::sequence((
            // version is DEFAULT
            self.asn.encode(),
            self.peering_api_uri.encode(),
        ))
    }

}

pub struct PadBuilder {
    asn: Asn,
    peering_api_uri: Https
}

impl PadBuilder {
    pub fn new(asn: Asn, peering_api_uri: Https) -> Self {
        Self {
            asn, peering_api_uri
        }
    }

    pub fn asn(&self) -> Asn {
        self.asn
    }

    pub fn set_asn(&mut self, asn: Asn) {
        self.asn = asn;
    }

    pub fn peering_api_uri(&self) -> &Https {
        &self.peering_api_uri
    }

    pub fn set_peering_api_uri(&mut self, peering_api_uri: Https) {
        self.peering_api_uri = peering_api_uri;
    }

    pub fn to_discovery(&self) -> PeeringApiDiscovery {
        PeeringApiDiscovery {
            asn: self.asn,
            peering_api_uri: self.peering_api_uri.clone()
        }
    }
    pub fn finalize<S: Signer>(
        self,
        mut sigobj: SignedObjectBuilder,
        signer: &S,
        issuer_key: &S::KeyId,
    ) -> Result<Pad, SigningError<S::Error>> {
        let content = self.to_discovery();
        let mut as_resources = AsResourcesBuilder::new();
        as_resources.blocks(|b| {
            b.push(content.asn)
        });
        sigobj.set_as_resources(as_resources.finalize());
        let signed = sigobj.finalize(
            Oid(oid::PEERING_API_DISCOVERY.0.into()),
            content.encode_ref().to_captured(Mode::Der).into_bytes(),
            signer,
            issuer_key,
        )?;
        Ok(Pad { signed, content })
    }
}