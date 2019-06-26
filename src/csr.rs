//! Certificate Signing Requests (CSR) for RPKI.
//!
//! Certificate Signing Requests, also called Certification Requests, for the
//! RPKI use the PKCS#10 Certification Requests defined in RFC2986, while
//! limiting the allowed extensions in section 6 of RFC6487.
//!
//! They are used in the exchange defined in section 3.4.1 of RFC6492 where a
//! child Certificate Authority requests a new certificate to be signed by
//! its parent CA.
//!
//! The CSR includes:
//! - a suggested subject
//! - the public key
//! - extensions:
//!     - basic constraints
//!     - key usage
//!     - extended key usage
//!     - subject information access
//! - a signature (to prove possession of the public key)
//!

use bcder::{decode, xerr};
use bcder::{Captured, Mode, OctetString, Oid, Tag};
use crate::{oid, uri};
use crate::cert::{KeyUsage, Sia, TbsCert};
use crate::crypto::PublicKey;
use crate::x509::{Name, SignedData, ValidationError};

//------------ Csr -----------------------------------------------------------

/// An RPKI Certificate Sign Request.
#[derive(Clone, Debug)]
pub struct Csr {
    /// The outer structure of the CSR.
    signed_data: SignedData,

    /// The content of the CSR.
    content: CsrContent
}

/// # Data Access
///
impl Csr {
    /// The subject name included on the CSR.
    ///
    /// TLDR; This field is useless and will be ignored by the issuing CA.
    ///
    /// This field is required by RFC2986, but RFC6487 says that in the RPKI
    /// its value SHOULD be empty when requesting new certificates, and MAY
    /// be non-empty only on subsequent re-issuance requests and only if the
    /// issuing CA has adopted a policy that allows re-use of the name
    /// (implying, but not saying, that the request should then include the
    /// previously allocated name).
    ///
    /// Issuing CAs MUST generate a unique name in the issued certificate.
    pub fn subject(&self) -> &Name {
        &self.content.subject
    }

    /// Returns the public key for the requested certificate. Note that
    /// validate() should be called to ensure that the requester has possession
    /// of the private key for this public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.content.public_key
    }

    /// Returns the cA field of the basic constraints extension if present, or
    /// false.
    pub fn basic_ca(&self) -> bool {
        self.content.attributes.basic_ca
    }


    /// Returns the desired KeyUsage
    pub fn key_usage(&self) -> KeyUsage {
        self.content.attributes.key_usage
    }

    /// Returns the optional desired extended key usage.
    pub fn extended_key_usage(&self) -> Option<&Captured> {
       self.content.attributes.extended_key_usage.as_ref()
    }

    /// Returns the desired ca repository
    pub fn ca_repository(&self) -> Option<&uri::Rsync> {
        self.content.attributes.sia.ca_repository()
    }

    /// Returns the desired rpki manifest uri
    pub fn rpki_manifest(&self) -> Option<&uri::Rsync> {
        self.content.attributes.sia.rpki_manifest()
    }

    /// Returns the desired rpki notify uri (for RRDP)
    pub fn rpki_notify(&self) -> Option<&uri::Https> {
        self.content.attributes.sia.rpki_notify()
    }

}

/// # Decode and Validate
///
impl Csr {
    /// Parse as a source as a certificate signing request.
    pub fn decode<S: decode::Source>(source: S) -> Result<Self, S::Err> {
        Mode::Der.decode(source, Self::take_from)
    }

    /// Takes an encoded CSR from the beginning of a constructed value.
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::from_constructed)
    }

    /// Parses the content of a certificate signing request.
    fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        let signed_data = SignedData::from_constructed(cons)?;
        let content = signed_data.data().clone().decode(CsrContent::take_from)?;

        Ok(Self { signed_data, content })
    }

    /// Validates the CSR against its internal public key
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.signed_data.verify_signature(self.public_key())
    }
}


#[derive(Clone, Debug)]
pub struct CsrContent {
    // version, MUST be 0
    subject: Name,
    public_key: PublicKey,
    attributes: CsrAttributes
}

impl CsrContent {
    /// Takes a value from the beginning of an encoded constructed value.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            cons.skip_u8_if(0)?; // version MUST be 0, cause v1
            let subject = Name::take_from(cons)?;
            let public_key = PublicKey::take_from(cons)?;
            let attributes = CsrAttributes::take_from(cons)?;
            Ok(CsrContent { subject, public_key, attributes })
        })
    }
}

#[derive(Clone, Debug)]
pub struct CsrAttributes {
    basic_ca: bool,
    key_usage: KeyUsage,
    extended_key_usage: Option<Captured>,
    sia: Sia
}

impl CsrAttributes {
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_constructed_if(Tag::CTX_0, |cons| {

            let mut basic_ca: Option<bool> = None;
            let mut key_usage: Option<KeyUsage> = None;
            let mut extended_key_usage: Option<Captured> = None;
            let mut sia: Option<Sia> = None;

            cons.take_sequence(|cons| {
                let id = Oid::take_from(cons)?;
                if id == oid::EXTENSION_REQUEST {
                    cons.take_set(|cons| { cons.take_sequence(|cons| {
                        while let Some(()) = cons.take_opt_sequence(|cons| {

                            let id = Oid::take_from(cons)?;
                            let _crit = cons.take_opt_bool()?;

                            let value = OctetString::take_from(cons)?;

                            Mode::Der.decode(value.to_source(), |content| {
                                if id == oid::CE_BASIC_CONSTRAINTS {
                                    TbsCert::take_basic_constraints(
                                        content, &mut basic_ca
                                    )
                                } else if id == oid::CE_KEY_USAGE {
                                    TbsCert::take_key_usage(
                                        content, &mut key_usage
                                    )
                                } else if id == oid::CE_EXTENDED_KEY_USAGE {
                                    TbsCert::take_extended_key_usage(
                                        content, &mut extended_key_usage
                                    )
                                } else if id == oid::PE_SUBJECT_INFO_ACCESS {
                                    TbsCert::take_subject_info_access(
                                        content, &mut sia
                                    )
                                } else {
                                    Err(decode::Malformed)
                                }
                            })?;


                            Ok(())
                        })? {};
                        Ok(())
                    })})
                } else {
                    xerr!(Err(decode::Malformed).map_err(Into::into))
                }
            })?;

            let basic_ca = basic_ca.ok_or_else(|| decode::Malformed)?;
            let key_usage = key_usage.ok_or_else(|| decode::Malformed)?;
            let sia = sia.ok_or_else(|| decode::Malformed)?;

            Ok(
                CsrAttributes {
                    basic_ca, key_usage, extended_key_usage, sia
                }
            )
        })
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod test {

    use std::str::FromStr;
    use super::*;

    #[test]
    fn parse_drl_csr() {
        let bytes = include_bytes!("../test-data/drl-csr.der");

        let csr = Csr::decode(bytes.as_ref()).unwrap();

        csr.validate().unwrap();

        assert!(csr.basic_ca());

        let ca_repo = uri::Rsync::from_str(
            "rsync://localhost:4404/rpki/Alice/Bob/Carol/3/"
        ).unwrap();
        assert_eq!(Some(&ca_repo), csr.ca_repository());


        let rpki_mft = uri::Rsync::from_str(
            "rsync://localhost:4404/rpki/Alice/Bob/Carol/3/IozwkwjtGls63XR8W2lo1wc7UoU.mnf"
        ).unwrap();
        assert_eq!(Some(&rpki_mft), csr.rpki_manifest());

        assert_eq!(None, csr.rpki_notify());
    }

}