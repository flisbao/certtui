#!/usr/bin/env python3
"""Gera as fixtures de revogação (OCSP e CRL) desta pasta.

FERRAMENTA GERADORA fora do projeto: usa Python + `cryptography`, não faz parte
do build nem do CI. Os artefatos gerados são commitados. Todas as chaves privadas
vivem só na memória deste processo e nunca são gravadas.

Os instantes são fixos (veja README.md) para que os testes usem um `FixedClock`
estável. Rode `./generate.sh` e depois confira com os comandos `openssl` do README.
"""
import datetime as dt
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

OUT = pathlib.Path(__file__).resolve().parent
UTC = dt.timezone.utc


def t(y, m, d, h=0):
    return dt.datetime(y, m, d, h, tzinfo=UTC)


NOT_BEFORE = t(2026, 1, 1)
NOT_AFTER = t(2036, 1, 1)
THIS_UPDATE = t(2026, 11, 1)
NEXT_UPDATE = t(2026, 12, 1)
OLD_THIS = t(2026, 10, 1)
OLD_NEXT = t(2026, 10, 8)
REVOKED_AT = t(2026, 10, 15)

SERIAL_GOOD, SERIAL_REVOKED, SERIAL_UNKNOWN = 0x1001, 0x1002, 0x1003
SERIAL_ABSENT = 0x1FFF


def name(cn):
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CertTui Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def new_key():
    return ec.generate_private_key(ec.SECP256R1())


def build_cert(subject_cn, key, issuer_cert, issuer_key, serial, *, ca=False, extra=()):
    issuer_name = issuer_cert.subject if issuer_cert is not None else name(subject_cn)
    signer = issuer_key if issuer_key is not None else key
    b = (
        x509.CertificateBuilder()
        .subject_name(name(subject_cn))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if issuer_cert is not None:
        b = b.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
            critical=False,
        )
    for ext, critical in extra:
        b = b.add_extension(ext, critical=critical)
    return b.sign(signer, hashes.SHA256())


def leaf_extras(cn):
    return [
        (x509.SubjectAlternativeName([x509.DNSName(cn)]), False),
        (
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier("http://ocsp.example.test/ocsp"),
                    ),
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier("http://ca.example.test/ca.der"),
                    ),
                ]
            ),
            False,
        ),
        (
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier("http://crl.example.test/ca.crl")],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            False,
        ),
    ]


def write_cert(stem, cert):
    (OUT / f"{stem}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (OUT / f"{stem}.der").write_bytes(cert.public_bytes(serialization.Encoding.DER))


def ocsp_response(cert, issuer, status, this, nxt, signer_key, responder_cert=None,
                  certs=(), revoked_at=None, reason=None):
    b = ocsp.OCSPResponseBuilder().add_response(
        cert=cert, issuer=issuer, algorithm=hashes.SHA1(), cert_status=status,
        this_update=this, next_update=nxt, revocation_time=revoked_at,
        revocation_reason=reason,
    )
    b = b.responder_id(ocsp.OCSPResponderEncoding.HASH, responder_cert or issuer)
    if certs:
        b = b.certificates(list(certs))
    return b.sign(signer_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def flip_last_byte(data):
    return data[:-1] + bytes([data[-1] ^ 0x01])


def der_len(n):
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def der_tlv(tag, body):
    return bytes([tag]) + der_len(len(body)) + body


def der_split(data):
    """Parte uma sequência de TLVs em [(tag, bytes_completos)]."""
    items, i = [], 0
    while i < len(data):
        tag = data[i]
        first = data[i + 1]
        if first < 0x80:
            length, hdr = first, 2
        else:
            n = first & 0x7F
            length, hdr = int.from_bytes(data[i + 2 : i + 2 + n], "big"), 2 + n
        items.append((tag, data[i : i + hdr + length], data[i + hdr : i + hdr + length]))
        i += hdr + length
    return items


def crl_without_next_update(crl_der, ca_key):
    """Remove `nextUpdate` do TBSCertList e reassina com a chave da CA."""
    (_, _, cl_body), = der_split(crl_der)
    tbs, _sigalg, _sig = der_split(cl_body)
    elems = der_split(tbs[2])
    # versão, assinatura, emissor, thisUpdate, nextUpdate, ...
    assert elems[4][0] in (0x17, 0x18), "nextUpdate esperado na posição 4"
    new_tbs = der_tlv(0x30, b"".join(e[1] for k, e in enumerate(elems) if k != 4))
    sig = ca_key.sign(new_tbs, ec.ECDSA(hashes.SHA256()))
    sig_bits = der_tlv(0x03, b"\x00" + sig)
    return der_tlv(0x30, new_tbs + _sigalg[1] + sig_bits)


def build_crl(ca_cert, ca_key, this, nxt, revoked=(), extra=()):
    b = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(this)
        .next_update(nxt)
        .add_extension(x509.CRLNumber(7), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False
        )
    )
    for serial, when, reason in revoked:
        r = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(when)
        if reason is not None:
            r = r.add_extension(x509.CRLReason(reason), critical=False)
        b = b.add_revoked_certificate(r.build())
    for ext, critical in extra:
        b = b.add_extension(ext, critical=critical)
    return b.sign(ca_key, hashes.SHA256())


def main():
    ca_key = new_key()
    ca = build_cert(
        "CertTui Revocation Test CA", ca_key, None, None, 1, ca=True,
        extra=[(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)],
    )
    write_cert("ca", ca)

    leaf_keys = {s: new_key() for s in (SERIAL_GOOD, SERIAL_REVOKED, SERIAL_UNKNOWN)}
    good = build_cert("good.example.test", leaf_keys[SERIAL_GOOD], ca, ca_key, SERIAL_GOOD, extra=leaf_extras("good.example.test"))
    revoked = build_cert("revoked.example.test", leaf_keys[SERIAL_REVOKED], ca, ca_key, SERIAL_REVOKED, extra=leaf_extras("revoked.example.test"))
    unknown = build_cert("unknown.example.test", leaf_keys[SERIAL_UNKNOWN], ca, ca_key, SERIAL_UNKNOWN, extra=leaf_extras("unknown.example.test"))
    write_cert("leaf-good", good)
    write_cert("leaf-revoked", revoked)
    write_cert("leaf-unknown", unknown)

    # Responders delegados: um com EKU OCSPSigning e um sem.
    resp_key = new_key()
    responder = build_cert(
        "CertTui OCSP Responder", resp_key, ca, ca_key, 0x2001,
        extra=[(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), False)],
    )
    noeku_key = new_key()
    responder_noeku = build_cert("CertTui Responder Sem EKU", noeku_key, ca, ca_key, 0x2002)
    write_cert("responder", responder)
    write_cert("responder-noeku", responder_noeku)

    G, R, U = ocsp.OCSPCertStatus.GOOD, ocsp.OCSPCertStatus.REVOKED, ocsp.OCSPCertStatus.UNKNOWN
    files = {
        "ocsp-good.der": ocsp_response(good, ca, G, THIS_UPDATE, NEXT_UPDATE, ca_key),
        "ocsp-revoked.der": ocsp_response(revoked, ca, R, THIS_UPDATE, NEXT_UPDATE, ca_key, revoked_at=REVOKED_AT, reason=x509.ReasonFlags.key_compromise),
        "ocsp-unknown.der": ocsp_response(unknown, ca, U, THIS_UPDATE, NEXT_UPDATE, ca_key),
        "ocsp-expired.der": ocsp_response(good, ca, G, OLD_THIS, OLD_NEXT, ca_key),
        "ocsp-bad-signature.der": flip_last_byte(ocsp_response(good, ca, G, THIS_UPDATE, NEXT_UPDATE, ca_key)),
        "ocsp-delegated.der": ocsp_response(good, ca, G, THIS_UPDATE, NEXT_UPDATE, resp_key, responder, certs=[responder]),
        "ocsp-delegated-no-eku.der": ocsp_response(good, ca, G, THIS_UPDATE, NEXT_UPDATE, noeku_key, responder_noeku, certs=[responder_noeku]),
        # Resposta válida, mas sobre o serial do cert "revoked": usada contra "good" (replay).
        "ocsp-other-cert.der": ocsp_response(revoked, ca, G, THIS_UPDATE, NEXT_UPDATE, ca_key),
        # OCSPResponse { responseStatus tryLater(3) } e unauthorized(6), sem responseBytes.
        "ocsp-try-later.der": bytes([0x30, 0x03, 0x0A, 0x01, 0x03]),
        "ocsp-unauthorized.der": bytes([0x30, 0x03, 0x0A, 0x01, 0x06]),
    }

    # Cadeia de 3: folha -> intermediária -> `ca`; ambas com AIA/CRL DP.
    int_key = new_key()
    inter = build_cert(
        "CertTui Intermediate CA", int_key, ca, ca_key, 0x4001, ca=True,
        extra=[(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)] + leaf_extras("intermediate.example.test"),
    )
    leaf_int = build_cert("leaf-int.example.test", new_key(), inter, int_key, 0x4002, extra=leaf_extras("leaf-int.example.test"))
    write_cert("intermediate", inter)
    write_cert("leaf-int", leaf_int)

    # CA cujo keyUsage não tem cRLSign, com uma folha e uma CRL assinadas por ela.
    ca2_key = new_key()
    ca2 = build_cert(
        "CertTui CA Sem cRLSign", ca2_key, None, None, 2, ca=True,
        extra=[(x509.KeyUsage(False, False, False, False, False, True, False, False, False), True)],
    )
    leaf_nocrl = build_cert("nocrlsign.example.test", new_key(), ca2, ca2_key, 0x3001, extra=leaf_extras("nocrlsign.example.test"))
    write_cert("ca-no-crlsign", ca2)
    write_cert("leaf-no-crlsign", leaf_nocrl)
    # Folha que diz ter sido emitida pela CA (mesmo issuer name) mas foi assinada por outra chave.
    forged = build_cert("forged.example.test", new_key(), ca, new_key(), SERIAL_REVOKED, extra=leaf_extras("forged.example.test"))
    write_cert("leaf-forged", forged)

    kc = x509.ReasonFlags.key_compromise
    crl_dp = lambda url: x509.IssuingDistributionPoint([x509.UniformResourceIdentifier(url)], None, False, False, None, False, False)
    crl_revoked = build_crl(ca, ca_key, THIS_UPDATE, NEXT_UPDATE, [(SERIAL_REVOKED, REVOKED_AT, kc)])
    ser = lambda c: c.public_bytes(serialization.Encoding.DER)
    files |= {
        "crl-with-revoked.der": ser(crl_revoked),
        "crl-without-leaf.der": ser(build_crl(ca, ca_key, THIS_UPDATE, NEXT_UPDATE, [(SERIAL_ABSENT, REVOKED_AT, kc)])),
        "crl-no-next-update.der": crl_without_next_update(ser(crl_revoked), ca_key),
        "crl-bad-signature.der": flip_last_byte(ser(crl_revoked)),
        "crl-stale.der": ser(build_crl(ca, ca_key, OLD_THIS, OLD_NEXT, [(SERIAL_REVOKED, REVOKED_AT, kc)])),
        "crl-delta.der": ser(build_crl(ca, ca_key, THIS_UPDATE, NEXT_UPDATE, [(SERIAL_REVOKED, REVOKED_AT, kc)], extra=[(x509.DeltaCRLIndicator(6), True)])),
        # IDP crítica cujo valor não é um IssuingDistributionPoint legível (assinada normalmente).
        "crl-idp-garbage.der": ser(build_crl(ca, ca_key, THIS_UPDATE, NEXT_UPDATE, [(SERIAL_ABSENT, REVOKED_AT, kc)], extra=[(x509.UnrecognizedExtension(x509.ObjectIdentifier("2.5.29.28"), b"\x04\x01\x00"), True)])),
        "crl-no-crlsign.der": ser(build_crl(ca2, ca2_key, THIS_UPDATE, NEXT_UPDATE, [])),
        # IssuingDistributionPoint com distributionPoint igual / diferente do CRL DP das folhas.
        "crl-idp-matching-dp.der": ser(build_crl(ca, ca_key, THIS_UPDATE, NEXT_UPDATE, [(SERIAL_REVOKED, REVOKED_AT, kc)], extra=[(crl_dp("http://crl.example.test/ca.crl"), True)])),
        "crl-idp-other-dp.der": ser(build_crl(ca, ca_key, THIS_UPDATE, NEXT_UPDATE, [(SERIAL_ABSENT, REVOKED_AT, kc)], extra=[(crl_dp("http://crl.example.test/other.crl"), True)])),
        # IssuingDistributionPoint: só certs de CA; não cobre as folhas.
        "crl-idp-ca-only.der": ser(build_crl(ca, ca_key, THIS_UPDATE, NEXT_UPDATE, [(SERIAL_REVOKED, REVOKED_AT, kc)], extra=[(x509.IssuingDistributionPoint(None, None, False, True, None, False, False), True)])),
    }
    for fname, data in files.items():
        (OUT / fname).write_bytes(data)
    print(f"{len(files)} arquivos + certificados gerados em {OUT}")


if __name__ == "__main__":
    main()
