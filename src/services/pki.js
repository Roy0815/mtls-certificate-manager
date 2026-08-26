'use strict';

const forge = require('node-forge');
const crypto = require('crypto');
const env = require('../config/env');

const pki = forge.pki;
const asn1 = forge.asn1;

// CA is long-lived (10y default) and generated once — 4096 bits for extra
// margin. Leaf certs are short-lived (1y default) and reissued whenever an
// admin clicks a button, so they use 2048 bits: still well above any
// current security recommendation for a 1-year cert, and RSA key generation
// in node-forge is pure JS (no native OpenSSL binding), where 4096-bit
// generation can take several seconds — bad UX for a "reissue" click that
// admins will trigger far more often than CA setup happens.
const CA_KEY_BITS = 4096;
const LEAF_KEY_BITS = 2048;

// forge's oids table only maps these id->name (one-directional _I_, not the
// two-directional _IN used for e.g. sha256WithRSAEncryption), so
// pki.oids['cRLNumber'] is undefined — use the dotted OIDs directly.
const OID_CRL_NUMBER = '2.5.29.20';
const OID_CRL_REASON = '2.5.29.21';

// RFC 5280 CRL reason codes.
const CRL_REASON = {
  superseded: 4,
  privilegeWithdrawn: 9,
};
const REASON_CODE_BY_APP_REASON = {
  reissued: CRL_REASON.superseded,
  manually_deactivated: CRL_REASON.privilegeWithdrawn,
};

function generateKeyPairAsync(bits) {
  return new Promise((resolve, reject) => {
    pki.rsa.generateKeyPair({ bits }, (err, keypair) => {
      if (err) reject(err);
      else resolve(keypair);
    });
  });
}

/** DER INTEGER-safe random 128-bit serial: prefix 00 if the high bit is set. */
function randomSerialHex() {
  const bytes = crypto.randomBytes(16);
  const hex = bytes.toString('hex');
  return bytes[0] & 0x80 ? `00${hex}` : hex;
}

function addDays(date, days) {
  const d = new Date(date.getTime());
  d.setUTCDate(d.getUTCDate() + days);
  return d;
}

async function generateCA(orgName) {
  const keys = await generateKeyPairAsync(CA_KEY_BITS);
  const cert = pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = randomSerialHex();

  const now = new Date();
  cert.validity.notBefore = now;
  cert.validity.notAfter = addDays(now, env.CA_VALIDITY_DAYS);

  const attrs = [
    { name: 'commonName', value: `${orgName} Root CA` },
    { name: 'organizationName', value: orgName },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true },
    {
      name: 'keyUsage',
      keyCertSign: true,
      cRLSign: true,
      digitalSignature: true,
      critical: true,
    },
    { name: 'subjectKeyIdentifier' },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  return {
    certPem: pki.certificateToPem(cert),
    privateKeyPem: pki.privateKeyToPem(keys.privateKey),
  };
}

/**
 * @param {string} caCertPem
 * @param {string} caPrivateKeyPem
 * @param {{commonName: string, email: string}} subject
 * @param {number} validityDays
 */
async function issueCertificate(caCertPem, caPrivateKeyPem, subject, validityDays) {
  const caCert = pki.certificateFromPem(caCertPem);
  const caKey = pki.privateKeyFromPem(caPrivateKeyPem);
  const keys = await generateKeyPairAsync(LEAF_KEY_BITS);

  const cert = pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = randomSerialHex();

  const notBefore = new Date();
  const notAfter = addDays(notBefore, validityDays);
  cert.validity.notBefore = notBefore;
  cert.validity.notAfter = notAfter;

  cert.setSubject([
    { name: 'commonName', value: subject.commonName },
    { name: 'emailAddress', value: subject.email },
  ]);
  cert.setIssuer(caCert.subject.attributes);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false, critical: true },
    {
      name: 'keyUsage',
      digitalSignature: true,
      keyEncipherment: true,
      critical: true,
    },
    { name: 'extKeyUsage', clientAuth: true },
    { name: 'subjectKeyIdentifier' },
    {
      name: 'authorityKeyIdentifier',
      keyIdentifier: caCert.generateSubjectKeyIdentifier().getBytes(),
    },
    {
      name: 'subjectAltName',
      altNames: [{ type: 1, value: subject.email }], // 1 = rfc822Name
    },
  ]);
  cert.sign(caKey, forge.md.sha256.create());

  return {
    certPem: pki.certificateToPem(cert),
    privateKeyPem: pki.privateKeyToPem(keys.privateKey),
    serial: cert.serialNumber,
    issuedAt: notBefore.toISOString(),
    expiresAt: notAfter.toISOString(),
  };
}

function buildPkcs12(certPem, privateKeyPem, caCertPem, password) {
  const cert = pki.certificateFromPem(certPem);
  const key = pki.privateKeyFromPem(privateKeyPem);
  const caCert = pki.certificateFromPem(caCertPem);
  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(key, [cert, caCert], password, {
    algorithm: 'aes256',
  });
  const der = asn1.toDer(p12Asn1).getBytes();
  return Buffer.from(der, 'binary');
}

// -- CRL ---------------------------------------------------------------
//
// node-forge has no CRL API at all (only certs/CSRs/PKCS#12), so this hand
// -builds a standard RFC 5280 CertificateList using forge's low-level ASN.1
// primitives — the same primitives forge's own x509.js uses internally to
// build certificates, so the encoding conventions below (time encoding,
// serial-as-hex-bytes INTEGER, signature BIT STRING framing) mirror what
// `node_modules/node-forge/lib/x509.js` does for certificates.

const JAN_1_2050 = new Date('2050-01-01T00:00:00Z');

function timeToAsn1(date) {
  if (date < JAN_1_2050) {
    return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.UTCTIME, false, asn1.dateToUtcTime(date));
  }
  return asn1.create(
    asn1.Class.UNIVERSAL,
    asn1.Type.GENERALIZEDTIME,
    false,
    asn1.dateToGeneralizedTime(date)
  );
}

function algorithmIdentifierAsn1(oid) {
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(oid).getBytes()),
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, ''),
  ]);
}

/**
 * @param {string} caCertPem
 * @param {string} caPrivateKeyPem
 * @param {Array<{serial: string, revokedAt: string, reason: 'reissued'|'manually_deactivated'}>} entries
 * @param {number} crlNumber - monotonically increasing per RFC 5280 §5.2.3
 * @param {number} validityDays - how far out `nextUpdate` is set
 * @returns {string} PEM-encoded CRL
 */
function buildCrl(caCertPem, caPrivateKeyPem, entries, crlNumber, validityDays) {
  const caCert = pki.certificateFromPem(caCertPem);
  const caKey = pki.privateKeyFromPem(caPrivateKeyPem);
  const sigOid = pki.oids['sha256WithRSAEncryption'];

  const thisUpdate = new Date();
  const nextUpdate = addDays(thisUpdate, validityDays);

  const revokedSeqEntries = entries.map((entry) => {
    const reasonCode = REASON_CODE_BY_APP_REASON[entry.reason];
    const reasonExt = pki.certificateExtensionToAsn1({
      id: OID_CRL_REASON,
      critical: false,
      value: asn1.create(
        asn1.Class.UNIVERSAL,
        asn1.Type.ENUMERATED,
        false,
        String.fromCharCode(reasonCode)
      ),
    });
    return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      asn1.create(
        asn1.Class.UNIVERSAL,
        asn1.Type.INTEGER,
        false,
        forge.util.hexToBytes(entry.serial)
      ),
      timeToAsn1(new Date(entry.revokedAt)),
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [reasonExt]),
    ]);
  });

  const crlNumberExt = pki.certificateExtensionToAsn1({
    id: OID_CRL_NUMBER,
    critical: false,
    value: asn1.create(
      asn1.Class.UNIVERSAL,
      asn1.Type.INTEGER,
      false,
      asn1.integerToDer(crlNumber).getBytes()
    ),
  });

  const tbsCertListValue = [
    // version: v2 (INTEGER 1) — required because crlExtensions/entry extensions are present
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, asn1.integerToDer(1).getBytes()),
    algorithmIdentifierAsn1(sigOid),
    pki.distinguishedNameToAsn1(caCert.subject),
    timeToAsn1(thisUpdate),
    timeToAsn1(nextUpdate),
  ];
  if (revokedSeqEntries.length > 0) {
    tbsCertListValue.push(
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, revokedSeqEntries)
    );
  }
  // crlExtensions: [0] EXPLICIT Extensions
  tbsCertListValue.push(
    asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [crlNumberExt]),
    ])
  );

  const tbsCertList = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, tbsCertListValue);

  const tbsDerBytes = asn1.toDer(tbsCertList).getBytes();
  const md = forge.md.sha256.create();
  md.update(tbsDerBytes);
  const signature = caKey.sign(md);

  const certificateList = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    tbsCertList,
    algorithmIdentifierAsn1(sigOid),
    asn1.create(
      asn1.Class.UNIVERSAL,
      asn1.Type.BITSTRING,
      false,
      String.fromCharCode(0x00) + signature
    ),
  ]);

  const der = asn1.toDer(certificateList).getBytes();
  const b64 = Buffer.from(der, 'binary').toString('base64');
  const lines = b64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN X509 CRL-----\n${lines}\n-----END X509 CRL-----\n`;
}

function getCertExpiry(certPem) {
  return pki.certificateFromPem(certPem).validity.notAfter;
}

module.exports = {
  generateCA,
  issueCertificate,
  buildPkcs12,
  buildCrl,
  getCertExpiry,
};
