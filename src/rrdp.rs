//! Parsing the XML representations.

#![cfg(feature = "rrdp")]

use std::{error, fmt, hash, io, str};
use std::convert::TryFrom;
use log::info;
use ring::digest;
use uuid::Uuid;
use crate::uri;
use crate::xml::decode::{Content, Error as XmlError, Reader, Name};


//------------ NotificationFile ----------------------------------------------

pub struct NotificationFile {
    pub session_id: Uuid,
    pub serial: u64,
    pub snapshot: UriAndHash,
    pub deltas: Vec<(u64, UriAndHash)>,
}

impl NotificationFile {
    pub fn parse<R: io::BufRead>(reader: R) -> Result<Self, XmlError> {
        let mut reader = Reader::new(reader);

        let mut session_id = None;
        let mut serial = None;
        let mut outer = reader.start(|element| {
            if element.name() != NOTIFICATION {
                return Err(XmlError::Malformed)
            }

            element.attributes(|name, value| match name {
                b"version" => {
                    if value.ascii_into::<u8>()? != 1 {
                        return Err(XmlError::Malformed)
                    }
                    Ok(())
                }
                b"session_id" => {
                    session_id = Some(value.ascii_into()?);
                    Ok(())
                }
                b"serial" => {
                    serial = Some(value.ascii_into()?);
                    Ok(())
                }
                _ => Err(XmlError::Malformed)
            })
        })?;

        let mut snapshot = None;
        let mut deltas = Vec::new();
        while let Some(mut content) = outer.take_opt_element(&mut reader,
                                                             |element| {
            match element.name() {
                SNAPSHOT => {
                    if snapshot.is_some() {
                        return Err(XmlError::Malformed)
                    }
                    let mut uri = None;
                    let mut hash = None;
                    element.attributes(|name, value| match name {
                        b"uri" => {
                            uri = Some(value.ascii_into()?);
                            Ok(())
                        }
                        b"hash" => {
                            hash = Some(value.ascii_into()?);
                            Ok(())
                        }
                        _ => Err(XmlError::Malformed)
                    })?;
                    match (uri, hash) {
                        (Some(uri), Some(hash)) => {
                            snapshot = Some(UriAndHash::new(uri, hash));
                            Ok(())
                        }
                        _ => Err(XmlError::Malformed)
                    }
                }
                DELTA => {
                    let mut serial = None;
                    let mut uri = None;
                    let mut hash = None;
                    element.attributes(|name, value| match name {
                        b"serial" => {
                            serial = Some(value.ascii_into()?);
                            Ok(())
                        }
                        b"uri" => {
                            uri = Some(value.ascii_into()?);
                            Ok(())
                        }
                        b"hash" => {
                            hash = Some(value.ascii_into()?);
                            Ok(())
                        }
                        _ => Err(XmlError::Malformed)
                    })?;
                    match (serial, uri, hash) {
                        (Some(serial), Some(uri), Some(hash)) => {
                            deltas.push((serial, UriAndHash::new(uri, hash)));
                            Ok(())
                        }
                        _ => Err(XmlError::Malformed)
                    }
                }
                _ => Err(XmlError::Malformed)
            }
        })? {
            content.take_end(&mut reader)?;
        }

        outer.take_end(&mut reader)?;
        reader.end()?;

        match (session_id, serial, snapshot) {
            (Some(session_id), Some(serial), Some(snapshot)) => {
                Ok(NotificationFile { session_id, serial, snapshot, deltas })
            }
            _ => Err(XmlError::Malformed)
        }
    }
}


//------------ ProcessSnapshot -----------------------------------------------

pub trait ProcessSnapshot {
    type Err: From<ProcessError>;

    fn meta(
        &mut self,
        session_id: Uuid,
        serial: u64,
    ) -> Result<(), Self::Err>;

    fn publish(
        &mut self,
        uri: uri::Rsync,
        data: &mut ObjectReader,
    ) -> Result<(), Self::Err>;

    fn process<R: io::BufRead>(
        &mut self,
        reader: R
    ) -> Result<(), Self::Err> {
        let mut reader = Reader::new(reader);
        
        let mut session_id = None;
        let mut serial = None;
        let mut outer = reader.start(|element| {
            if element.name() != SNAPSHOT {
                info!("Bad outer: not snapshot, but {:?}", element.name());
                return Err(XmlError::Malformed)
            }
            element.attributes(|name, value| match name {
                b"version" => {
                    if value.ascii_into::<u8>()? != 1 {
                        info!("Bad version");
                        return Err(XmlError::Malformed)
                    }
                    Ok(())
                }
                b"session_id" => {
                    session_id = Some(value.ascii_into()?);
                    Ok(())
                }
                b"serial" => {
                    serial = Some(value.ascii_into()?);
                    Ok(())
                }
                _ => {
                    info!("Bad attribute on snapshot.");
                    Err(XmlError::Malformed)
                }
            })
        }).map_err(Into::into)?;

        match (session_id, serial) {
            (Some(session_id), Some(serial)) => {
                self.meta(session_id, serial)?;
            }
            _ => {
                info!("Missing session or serial");
                return Err(ProcessError::malformed().into())
            }
        }

        loop {
            let mut uri = None;
            let inner = outer.take_opt_element(&mut reader, |element| {
                if element.name() != PUBLISH {
                info!("Bad inner: not publish");
                    return Err(ProcessError::malformed())
                }
                element.attributes(|name, value| match name {
                    b"uri" => {
                        uri = Some(value.ascii_into()?);
                        Ok(())
                    }
                    _ => {
                        info!("Bad attribute on publish.");
                        Err(ProcessError::malformed())
                    }
                })
            })?;
            let mut inner = match inner {
                Some(inner) => inner,
                None => break
            };
            let uri = match uri {
                Some(uri) => uri,
                None => return Err(ProcessError::malformed().into())
            };
            ObjectReader::process_text(&mut inner, &mut reader, |reader| {
                self.publish(uri, reader)
            })?;
            inner.take_end(&mut reader).map_err(Into::into)?;
        }

        outer.take_end(&mut reader).map_err(Into::into)?;
        reader.end().map_err(Into::into)?;
        Ok(())
    }
}


//------------ ProcessDelta --------------------------------------------------

pub trait ProcessDelta {
    type Err: From<ProcessError>;

    fn meta(
        &mut self,
        session_id: Uuid,
        serial: u64,
    ) -> Result<(), Self::Err>;

    fn publish(
        &mut self,
        uri: uri::Rsync,
        hash: Option<Hash>,
        data: &mut ObjectReader,
    ) -> Result<(), Self::Err>;

    fn withdraw(
        &mut self,
        uri: uri::Rsync,
        hash: Hash,
    ) -> Result<(), Self::Err>;


    fn process<R: io::BufRead>(
        &mut self,
        reader: R
    ) -> Result<(), Self::Err> {
        let mut reader = Reader::new(reader);
        
        let mut session_id = None;
        let mut serial = None;
        let mut outer = reader.start(|element| {
            if element.name() != DELTA {
                return Err(ProcessError::malformed())
            }
            element.attributes(|name, value| match name {
                b"version" => {
                    if value.ascii_into::<u8>()? != 1 {
                        return Err(ProcessError::malformed())
                    }
                    Ok(())
                }
                b"session_id" => {
                    session_id = Some(value.ascii_into()?);
                    Ok(())
                }
                b"serial" => {
                    serial = Some(value.ascii_into()?);
                    Ok(())
                }
                _ => Err(ProcessError::malformed())
            })
        })?;

        match (session_id, serial) {
            (Some(session_id), Some(serial)) => {
                self.meta(session_id, serial)?;
            }
            _ => return Err(ProcessError::malformed().into())
        }

        loop {
            let mut action = None;
            let mut uri = None;
            let mut hash = None;
            let inner = outer.take_opt_element(&mut reader, |element| {
                match element.name() {
                    PUBLISH => action = Some(Action::Publish),
                    WITHDRAW => action = Some(Action::Withdraw),
                    _ => return Err(ProcessError::malformed()),
                };
                element.attributes(|name, value| match name {
                    b"uri" => {
                        uri = Some(value.ascii_into()?);
                        Ok(())
                    }
                    b"hash" => {
                        hash = Some(value.ascii_into()?);
                        Ok(())
                    }
                    _ => Err(ProcessError::malformed())
                })
            })?;
            let mut inner = match inner {
                Some(inner) => inner,
                None => break
            };
            let uri = match uri {
                Some(uri) => uri,
                None => return Err(ProcessError::malformed().into())
            };
            match action.unwrap() { // Or we'd have exited already.
                Action::Publish => {
                    ObjectReader::process_text(
                        &mut inner, &mut reader,
                        |reader| self.publish(uri, hash, reader)
                    )?;
                }
                Action::Withdraw => {
                    let hash = match hash {
                        Some(hash) => hash,
                        None => return Err(ProcessError::malformed().into())
                    };
                    self.withdraw(uri, hash)?;
                }
            }
            inner.take_end(&mut reader).map_err(Into::into)?;
        }
        outer.take_end(&mut reader).map_err(Into::into)?;
        reader.end().map_err(Into::into)?;
        Ok(())
    }

}


//------------ UriAndHash ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct UriAndHash {
    uri: uri::Https,
    hash: Hash,
}

impl UriAndHash {
    pub fn new(uri: uri::Https, hash: Hash) -> Self {
        UriAndHash { uri, hash }
    }

    pub fn uri(&self) -> &uri::Https {
        &self.uri
    }

    pub fn hash(&self) -> &Hash {
        &self.hash
    }
}


//------------ Hash ----------------------------------------------------------

/// The hash of RRDP files.
///
/// Since RRDP exclusively uses SHA-256, this is essentially a wrapper around
/// a 32 byte array.
#[derive(Clone, Copy, Eq, hash::Hash, PartialEq)]
#[repr(transparent)]
pub struct Hash([u8; 32]);

impl Hash {
    /// Returns a reference to the octets as a slice.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }
}


//--- From, TryFrom, and FromStr

impl From<[u8;32]> for Hash {
    fn from(value: [u8;32]) -> Hash {
        Hash(value)
    }
}

impl From<Hash> for [u8; 32] {
    fn from(src: Hash) -> Self {
        src.0
    }
}

impl<'a> TryFrom<&'a [u8]> for Hash {
    type Error = std::array::TryFromSliceError;

    fn try_from(src: &'a [u8]) -> Result<Self, Self::Error> {
        TryFrom::try_from(src).map(Hash)
    }
}

impl TryFrom<digest::Digest> for Hash {
    type Error = AlgorithmError;

    fn try_from(digest: digest::Digest) -> Result<Self, Self::Error> {
        // XXX This doesn’t properly check the algorithm.
        TryFrom::try_from(
            digest.as_ref()
        ).map(Hash).map_err(|_| AlgorithmError(()))
    }
}

impl str::FromStr for Hash {
    type Err = ParseHashError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64 {
            return Err(ParseHashError::bad_length())
        }
        let mut res = [0u8; 32];
        let mut s = s.chars();
        for octet in &mut res {
            let first = s.next().ok_or_else(
                ParseHashError::bad_chars
            )?.to_digit(16).ok_or_else(
                ParseHashError::bad_chars
            )?;
            let second = s.next().ok_or_else(
                ParseHashError::bad_chars
            )?.to_digit(16).ok_or_else(
                ParseHashError::bad_chars
            )?;
            *octet = (first << 4 | second) as u8;
        }
        Ok(Hash(res))
    }
}


//--- AsRef

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}


//--- PartialEq
//
// PartialEq<Self> and Eq are derived.

impl PartialEq<digest::Digest> for Hash {
    fn eq(&self, other: &digest::Digest) -> bool {
        // XXX This doesn’t properly check the algorithm.
        self.0.as_ref() == other.as_ref()
    }
}


//--- Display and Debug

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &ch in self.as_slice() {
            write!(f, "{:02x}", ch)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Hash({})", self)
    }
}


//------------ Action --------------------------------------------------------

enum Action {
    Publish,
    Withdraw,
}


//------------ ObjectReader --------------------------------------------------

pub struct ObjectReader<'a>(
    base64::read::DecoderReader<'a, &'a [u8]>
);

impl<'a> ObjectReader<'a> {
    fn process_text<R, T, E, F> (
        content: &mut Content,
        reader: &mut Reader<R>,
        op: F
    ) -> Result<T, E>
    where
        R: io::BufRead,
        E: From<ProcessError>,
        F: FnOnce(&mut ObjectReader) -> Result<T, E>
    {
        let data_b64: Vec<_> = content.take_text(reader,  |text| {
            Ok(text.to_ascii()?.as_bytes().iter().filter_map(|b| {
                    if b.is_ascii_whitespace() { None }
                    else { Some(*b) }
            }).collect())
        })?;
        let mut data_b64 = data_b64.as_slice();
        op(
            &mut ObjectReader(base64::read::DecoderReader::new(
                &mut data_b64, base64::STANDARD
            ))
        )
    }
}

impl<'a> io::Read for ObjectReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.0.read(buf)
    }
}


//------------ Xml Names -----------------------------------------------------

const NS: &[u8] = b"http://www.ripe.net/rpki/rrdp";
const NOTIFICATION: Name = Name::qualified(NS, b"notification");
const SNAPSHOT: Name = Name::qualified(NS, b"snapshot");
const DELTA: Name = Name::qualified(NS, b"delta");
const PUBLISH: Name = Name::qualified(NS, b"publish");
const WITHDRAW: Name = Name::qualified(NS, b"withdraw");


//============ Errors ========================================================

//------------ AlgorithmError ------------------------------------------------

/// A digest was of the wrong algorithm.
#[derive(Clone, Copy, Debug)]
pub struct AlgorithmError(());

impl fmt::Display for AlgorithmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("algorithm mismatch")
    }
}

impl error::Error for AlgorithmError { }


//------------ ParseHashError ------------------------------------------------

/// An error happened while parsing a hash.
#[derive(Clone, Copy, Debug)]
pub struct ParseHashError(&'static str);

impl ParseHashError {
    const fn bad_length() -> Self {
        ParseHashError("invalid length")
    }

    const fn bad_chars() -> Self {
        ParseHashError("invalid characters")
    }
}

impl fmt::Display for ParseHashError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl error::Error for ParseHashError { }


//------------ ProcessError --------------------------------------------------

/// An error occurred while processing RRDP data.
#[derive(Debug)]
pub enum ProcessError {
    /// An IO error happened.
    Io(io::Error),

    /// The XML was not correctly formed.
    Xml(XmlError),
}

impl ProcessError {
    fn malformed() -> Self {
        ProcessError::Xml(XmlError::Malformed)
    }
}

impl From<io::Error> for ProcessError {
    fn from(err: io::Error) -> Self {
        ProcessError::Io(err)
    }
}

impl From<XmlError> for ProcessError {
    fn from(err: XmlError) -> Self {
        ProcessError::Xml(err)
    }
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProcessError::Io(ref inner) => inner.fmt(f),
            ProcessError::Xml(ref inner) => inner.fmt(f)
        }
    }
}

impl error::Error for ProcessError { }


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    pub struct Test;

    impl ProcessSnapshot for Test {
        type Err = ProcessError;

        fn meta(
            &mut self,
            _session_id: Uuid,
            _serial: u64,
        ) -> Result<(), Self::Err> {
            Ok(())
        }

        fn publish(
            &mut self,
            _uri: uri::Rsync,
            _data: &mut ObjectReader,
        ) -> Result<(), Self::Err> {
            Ok(())
        }
    }

    impl ProcessDelta for Test {
        type Err = ProcessError;

        fn meta(
            &mut self,
            _session_id: Uuid,
            _serial: u64,
        ) -> Result<(), Self::Err> {
            Ok(())
        }

        fn publish(
            &mut self,
            _uri: uri::Rsync,
            _hash: Option<Hash>,
            _data: &mut ObjectReader,
        ) -> Result<(), Self::Err> {
            Ok(())
        }

        fn withdraw(
            &mut self,
            _uri: uri::Rsync,
            _hash: Hash,
        ) -> Result<(), Self::Err> {
            Ok(())
        }
    }

    #[test]
    fn ripe_notification() {
        NotificationFile::parse(
            include_bytes!("../test-data/ripe-notification.xml").as_ref()
        ).unwrap();
    }

    #[test]
    fn ripe_snapshot() {
        <Test as ProcessSnapshot>::process(
            &mut Test,
            include_bytes!("../test-data/ripe-snapshot.xml").as_ref()
        ).unwrap();
    }

    #[test]
    fn ripe_delta() {
        <Test as ProcessDelta>::process(
            &mut Test,
            include_bytes!("../test-data/ripe-delta.xml").as_ref()
        ).unwrap();
    }
}
