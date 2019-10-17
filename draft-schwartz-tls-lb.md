---
docname: draft-schwartz-tls-lb-latest
title: TLS Metadata for Load Balancers
abbrev: TLS-LB
category: std

ipr: trust200902
area: sec
workgroup: tls
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: B. Schwartz
    name: Benjamin M. Schwartz
    organization: Google LLC
    email: bemasc@google.com

informative:
  PROXY:
    title: The PROXY protocol
    author:
      name: Willy Tarreau
      org: HAProxy Technologies
    date: 2017/03/10
    target: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt

--- abstract

A load balancer that does not terminate TLS may wish to provide some information to the backend server, in addition to forwarding TLS data.  This draft proposes a protocol between load balancers and backends that enables secure, efficient delivery of TLS with additional information.  The need for such a protocol has recently become apparent in the context of split mode ESNI.

--- middle

# Conventions and Definitions

{::boilerplate bcp14}

Data encodings are expressed in the TLS 1.3 presentation language, as defined in Section 3 of {{!TLS13=RFC8446}}.

# Background

A load balancer is a server or bank of servers that acts as an intermediary between the client and a range of backend servers.  As the name suggests, a load balancer’s primary function is to ensure that client traffic is spread evenly across the available backend servers.  However load balancers also serve many other functions, such as identifying connections intended for different backends and forwarding them appropriately, or dropping connections that are deemed malicious.

A load balancer operates at a specific point in the protocol stack, forwarding e.g. IP packets, TCP streams, TLS contents, HTTP requests, etc.  Most relevant to this proposal are TCP and TLS load balancers.  TCP load balancers terminate the TCP connection with the client and establish a new TCP connection to the selected backend, bidirectionally copying the TCP contents between these two connections.  TLS load balancers additionally terminate the TLS connection, forwarding the plaintext to the backend server (typically inside a new TLS connection).  TLS load balancers must therefore hold the private keys for the domains they serve.

When a TCP load balancer forwards a TLS stream, the load balancer has no way to incorporate additional information into the stream.  Insertion of any additional data would cause the connection to fail.  However, the load-balancer and backend can share additional information if they agree to speak a new protocol.  The most popular protocol used for this purpose is currently the PROXY protocol {{PROXY}}, developed by HAPROXY.  This protocol prepends a plaintext collection of metadata (e.g. client IP address) onto the TCP socket.  The backend can parse this metadata, then pass the remainder of the stream to its TLS library.

The PROXY protocol is effective and widely used, but it offers no confidentiality or integrity protection, and therefore might not be suitable when the load balancer and backend communicate over the public internet.  It also does not offer a way for the backend to reply.

# Goals

*   Enable TCP load balancers to forward metadata to the backend.
*   Enable backends to reply.
*   Reduce the need for TLS-terminating load balancers.
*   Ensure confidentiality and integrity for all forwarded metadata.
*   Enable split ESNI architectures.
*   Prove to the backend that the load balancer intended to associate this metadata with this connection.
*   Achieve good CPU and memory efficiency.
*   Don’t impose additional latency.
*   Support backends that receive a mixture of direct and load-balanced TLS.
*   Support use in QUIC.
*   Enable simple and safe implementation.

# Overview

The proposed protocol supports a two-way exchange between a load balancer and a backend server.  It works by prepending information to the TLS handshake:

         +-----------+ +-----------+ +-----------+
         | Backend A | | Backend B | | Backend C |
         +-----------+ +-----------+ +-----------+
                           \/   /\
    4. EncryptedProxyData[ \/   /\  2. EncryptedProxyData[
        got SNI info]      \/   /\       SNI="secret.b",
    5. ServerHello, etc.   \/   /\       client=2, etc.]
                           \/   /\  3. ClientHello (verbatim)
                           \/   /\
                      +---------------+
                      | Load balancer |
                      +---------------+
                           \/   /\
    6. ServerHello, etc.   \/   /\  1. ClientHello[
       (verbatim)          \/   /\       ESNI=enc("secret.b")]
                           \/   /\
          +-----------+ +-----------+ +-----------+
          |  Client 1 | |  Client 2 | |  Client 3 |
          +-----------+ +-----------+ +-----------+
{: #diagram title="Data flow diagram"}

# Encoding

A ProxyExtension is identical in form to a standard TLS Extension (Section 4.2 of {{TLS13}}), with a new identifier space for the extension types.

    struct {
      ProxyExtensionType extension_type;
      opaque extension_data<0..2^16-1>;
    } ProxyExtension;

ProxyExtensions can be sent in an upstream (to the backend) or downstream (to the load balancer) direction

    enum {
      upstream(0),
      downstream(1),
      (255)
    } ProxyDataDirection;

The ProxyData contains a set of ProxyExtensions.

    struct {
      ProxyDataDirection direction;
      ProxyExtension proxy_data<0..2^16-1>;
    } ProxyData;

The EncryptedProxyData structure contains metadata associated with the original ClientHello (Section 4.1.2 of {{TLS13}}), encrypted with a pre-shared key that is configured out of band.

    struct {
      opaque psk_identity<1..2^16-1>;
      opaque nonce<8..2^16-1>
      opaque encrypted_proxy_data<1..2^16-1>;
    } EncryptedProxyData;

- psk_identity: The identity of a PSK previously agreed upon by the load balancer and the backend.  Including the PSK identity allows for updating the PSK without disruption.
- nonce: Non-repeating initializer for the AEAD.  This prevents an attacker from observing whether the same ClientHello is marked with different metadata over time.
- encrypted_proxy_data: AEAD-Encrypt(key, nonce, additional_data=ClientHello, plaintext=ProxyData).  The key and AEAD function are agreed out of band and associated with psk_identity.

When the load balancer receives a ClientHello, it serializes any relevant metadata into an upstream ProxyData, then encrypts it with the ClientHello as additional data to produce the EncryptedProxyData.  The backend's reply is a downstream ProxyData struct, also transmitted as an EncryptedProxyData using the ClientHello as additional data.  Recipients in each case MUST verify that ProxyData.direction has the expected value, and discard the connection if it does not.

The downstream ProxyData SHOULD NOT contain any ProxyExtensionType values that were not present in the upstream ProxyData.

# Defined ProxyExtensions

Like a standard TLS Extension, a ProxyExtension is identified by a 2-byte type number.  Load balancers MUST only include extensions that are specified for use in ProxyData.  Backends MUST ignore any extensions that they do not recognize.

There are initially five type numbers allocated:

    enum {
      padding(0),
      network_address(1),
      esni_inner(2),
      overload(3),
      ratchet(4),
      (65535)
    } ProxyExtensionType;

## padding

The "padding" extension functions as described in {{!RFC7685}}.  It is used here to avoid leaking information about the other extensions.

## network_address

The "network_address" extension functions as described in {{!I-D.kinnear-tls-client-net-address}}.  It conveys the client IP address observed by the load balancer.  Backends that make use of this extension SHOULD include an empty network_address value in the downstream ProxyData.

## esni_inner

The "esni_inner" extension can only be used if the ClientHello contains the encrypted_server_name extension {{!ESNI=I-D.ietf-tls-esni}}.  The upstream extension_data is the ClientESNIInner (Section 5.1.1 of {{ESNI}}), which contains the true SNI and nonce.  This is useful when the load balancer knows the ESNI private key and the backend does not, i.e. split mode ESNI.

## overload

In the upstream ProxyData, the "overload" extension contains a single uint16 indicating the approximate proportion of connections that are being routed to this server as a fraction of 65535.  If there is only one server, load balancers SHOULD set the value to 65535 or omit this extension.

In the downstream ProxyData, the value is an OverloadValue:

    enum {
      nominal(0),
      drain(1),
      reject(2),
      (255)
    } OverloadState;
    struct {
      OverloadState state;
      uint16 load;
      uint32 ttl;
    } OverloadValue;

When OverloadValue.state is "nominal", the backend is accepting connections normally.  The "drain" state indicates that the backend is accepting this connection, but would prefer not to receive additional connections.  A value of "reject" indicates that the backend did not accept this connection.  When sending a "reject" response, the backend SHOULD close the connection without sending a ServerHello.

OverloadValue.load indicates the relative load state of the responding backend server, in arbitrary units.  All backend servers for an origin SHOULD report load values in the same scale.

The load balancer SHOULD treat this information as valid for OverloadValue.ttl seconds, or until it receives another OverloadValue from that server.

Load balancers that have multiple available backends for an origin SHOULD avoid connecting to servers that are in the "drain" or "reject" state.  When a connection is rejected, the load balancer MAY retry that connection by sending the ClientHello to a different backend server.  When multiple servers are in the "nominal" state, the load balancer should direct more connections to servers with smaller OverloadValue.load.

When there is a server in an unknown state, the load balancer SHOULD direct at least one connection to it, in order to refresh its OverloadState.

If all servers are in the "drain" or "reject" state, the load balancer SHOULD drop the connection.

## ratchet

If the backend server is reachable without traversing the load balancer, and an adversary can observe packets on the link between the load balancer and the backend, then the adversary can execute a replay flooding attack, sending the backend server duplicate copies of observed EncryptedProxyData and ClientHello.  This attack can waste server resources on the Diffie-Hellman operations required to process the ClientHello, resulting in denial of service.

The "ratchet" extension reduces the impact of such an attack on the backend server by allowing the backend to reject these duplicates after decrypting the ProxyData.  (This decryption uses only a symmetric cipher, so it is expected to be much faster than typical Diffie-Hellman operations.)  Its upstream payload consists of a RatchetValue:

    struct {
      uint64 index;
      uint64 floor;
    } RatchetValue;

The load balancer initializes `index` to a random value, and executes the following procedure:

1. For each new forwarded connection (to the same server under the same psk_identity), increment `index`.
2. Set `floor` to the `index` of the earliest connection that has not yet been connected or closed.

The backend server initializes `floor` upon receiving a RatchetValue for the first time, and then executes the following procedure:

1. Define `a >= b` if the most significant bit of `a - b` is 0.
2. Let `newValue` be the RatchetValue in the ProxyData.
3. If `newValue.index < floor` , ignore the connection.
4. If `newValue.floor >= floor`, set `floor` to `newValue.floor`.
5. OPTIONALLY, ignore the connection if `newValue.index` has been seen recently.  This can be implemented efficiently by keeping track of index values greater than `floor` that appear to have been skipped.

With these measures in place, replays can be rejected without processing the ClientHello.

# Use with TLS over TCP

When forwarding a TLS stream over TCP, the load balancer SHOULD send a ProxyHeader at the beginning of the stream:

    struct {
      uint8 opaque_type = 0;
      ProtocolVersion version = 0;
      uint16 length = length(ProxyHeader.contents);
      EncryptedProxyData contents;
    } ProxyHeader;

The opaque_type field ensures that this header is distinguishable from an ordinary TLS connection, whose first byte is always 22 (ContentType = handshake in Section 5.1 of {{TLS13}}).  This structure matches the layout of TLSPlaintext with a ContentType of “invalid”, potentially simplifying parsing.

Following the ProxyHeader, the load balancer MUST send the full contents of the TCP stream, exactly as received from the client.  The backend will observe the ProxyHeader, immediately followed by a TLSPlaintext frame containing the ClientHello.  The backend will decrypt the ProxyHeader using the ClientHello as associated data, and process the ClientHello and the remainder of the stream as standard TLS.

When receiving a ProxyHeader with an unrecognized version, the backend SHOULD ignore this ProxyHeader and proceed as if the following byte were the first byte received.

Similarly, the backend SHOULD reply with the downstream EncryptedProxyData in a ProxyHeader, followed by the normal TLS stream, beginning with a TLSPlaintext frame containing the ServerHello.  If the downstream ProxyHeader is not present, has an unrecognized version number,
or produces an error, the load balancer SHOULD proxy the rest of the stream regardless.

# Use with QUIC

A QUIC load balancer provides this service by extracting the ClientHello from any client Initial packet {{!I-D.ietf-quic-tls}}.  A multi-tenant load balancer needs to perform this extraction anyway in order to determine where the connection should be forwarded, either by SNI or ESNI.

Extracting a TLS ClientHello from a QUIC handshake is a version-dependent action, so a load balancer cannot support unrecognized versions of QUIC.  If the load balancer receives a packet with an unrecognized QUIC version, it MUST reply with a VersionNegotiation packet indicating the supported versions (currently only version 1).  If the backend applies downgrade protection, it SHOULD account for the impact of the load balancer.

In QUIC version 1, each handshake begins with an Initial packet sent by the client.  This packet uses the QUIC "long header" packet form, starting with a "fixed bit" of 1 and a "frame type" of 0x0.

    +-+-+-+-+-+-+-+-+
    |1|1| 0 |R R|P P|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Version (32)                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | DCID Len (8)  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |               Destination Connection ID (0..160)            ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | SCID Len (8)  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                 Source Connection ID (0..160)               ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Token Length (i)                    ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            Token (*)                        ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           Length (i)                        ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Packet Number (8/16/24/32)               ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Payload (*)                        ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
{: #initial-format title="QUIC Initial Packet"}

A client Initial packet contains a complete ClientHello, in a CRYPTO frame in the payload.  The load balancer extracts this ClientHello in order to compute the upstream EncryptedProxyData, and the backend uses it to compute the reply.

TODO: Confirm that HelloRetryRequest elicits an Initial containing a complete ClientHello.  The QUIC draft text is unclear.

To send an EncryptedProxyData along with an initial, the sender constructs a new packet with a header copied from the Initial, but with a new version (0xTBD1) that is only used for ProxyData.  Its payload consists of the old Initial's version number (currently always 1) and the EncryptedProxyData.

    +-+-+-+-+-+-+-+-+
    |1|1| 0 |R R|P P|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                Proxy Data Version, 0xTBD1 (32)                |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | DCID Len (8)  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |               Destination Connection ID (0..160)            ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | SCID Len (8)  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                 Source Connection ID (0..160)               ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Token Length (i)                    ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            Token (*)                        ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         New Length (i)                      ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Packet Number (8/16/24/32)               ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Initial Version (32)                   ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       EncryptedProxyData                    ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
{: #new-packet-format title="EncryptedProxyData packet to the backend"}

The sender then forwards the Initial unmodified, except for replacing its Version number with 0xTBD2.  All other QUIC packets are forwarded entirely unmodified.

The recipient, upon receipt of an Initial packet with QUIC version 0xTBD1 or 0xTBD2, waits for a second Initial packet with the other version and matching connection IDs, token, and packet number.  When both packets have been received, the backend can reconstruct the original Initial packet and decrypt the EncryptedProxyData.

If the second packet is not received within a brief time period (e.g. 100 ms), the recipient SHOULD discard the first packet.

This procedure is designed to bind both packets together without altering the size of the original Initial, which QUIC uses for path MTU detection.  Load balancers SHOULD apply this procedure to the Client Initial and the upstream ProxyData, and backends SHOULD apply it to the Server Initial and the downstream ProxyData.

Note that there is no explicit packet loss recovery for the ProxyData packet.  Instead, we rely on the QUIC implementation to retransmit the Initial if it is discarded.  Accordingly, senders MUST retransmit the ProxyData packet along with any retransmitted Initial.  Load balancers MAY retransmit the Client Initial and upstream ProxyData if no reply is received, and recipients MUST ignore ProxyData associated with a duplicate Initial.

# Configuration
The method of configuring of the PSK on the load balancer and backend is not specified here.  However, the PSK MAY be represented as a ProxyKey:

    struct {
      ProtocolVersion version = 0;
      opaque psk_identity<1..2^16-1>;
      CipherSuite cipher_suite;
      opaque key<16..2^16-1>
    } ProxyKey;

# Security considerations

## Integrity

This protocol is intended to provide both parties with a strong guarantee of integrity for the metadata they receive.  For example, an active attacker cannot take metadata intended for one stream and attach it to another, because each stream will have a unique ClientHello, and the metadata is bound to the ClientHello by AEAD.

One exception to this protection is in the case of an attacker who deliberately reissues identical ClientHello messages.  An attacker who reuses a ClientHello can also reuse the metadata associated with it, if they can first observe the EncryptedProxyData transferred between the load balancer and the backend.  This could be used by an attacker to reissue data originally generated by a true client (e.g. as part of a 0-RTT replay attack), or it could be used by a group of adversaries who are willing to share a single set of client secrets while initiating different sessions, in order to reuse metadata that they find helpful.

As such, the backend SHOULD treat this metadata as advisory.

## Confidentiality

This protocol is intended to maintain confidentiality of the metadata transferred between the load balancer and backend, especially the ESNI plaintext and the client IP address.  An observer between the client and the load balancer does not observe this protocol at all, and an observer between the load balancer and backend observes only ciphertext.

However, an adversary who can monitor both of these links can easily observe that a connection from the client to the load balancer is shortly followed by a connection from the load balancer to a backend, with the same ClientHello.  This reveals which backend server the client intended to visit.  In many cases, the choice of backend server could be the sensitive information that ESNI is intended to protect.

# IANA Considerations

Need to create a new ProxyExtensionType registry.

Need to allocate TBD as a reserved QUIC version code.

--- back

# Acknowledgements

This is an elaboration of an idea proposed by Eric Rescorla during the development of ESNI.  Thanks to David Schinazi, David Benjamin, and Piotr Sikora for suggesting important improvements.


# Open Questions

Should the ProxyExtensionType registry have a reserved range for private extensions?

Would it be secure to bind only to ClientHello.random?  Or should we bind to a hash of the ClientHello instead of the ClientHello itself?  This might reduce the amount of buffering required at the load balancer.

Should the downstream ProxyData be bound to the upstream ProxyData?
