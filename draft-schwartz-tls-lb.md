docname: draft-schwartz-tls-lb-latest
title: TLS Metadata for Load Balancers (TLS-LB)

Status: Draft


# Abstract

A load balancer that does not terminate TLS may wish to provide some information to the backend server, in addition to forwarding TLS data.  This draft proposes a protocol between load balancers and backends that enables secure, efficient delivery of TLS with additional information.  The need for such a protocol has recently become apparent in the context of split mode ESNI.


# Background

A load balancer is a server or bank of servers that acts as an intermediary between the client and a range of backend servers.  As the name suggests, a load balancer’s primary function is to ensure that client traffic is spread evenly across the available backend servers.  However load balancers also serve many other functions, such as identifying connections intended for different backends and forwarding them appropriately, or dropping connections that are deemed malicious.

A load balancer operates at a specific point in the protocol stack, forwarding e.g. IP packets, TCP streams, TLS contents, HTTP requests, etc.  Most relevant to this proposal are TCP and TLS load balancers.  TCP load balancers terminate the TCP connection with the client and establish a new TCP connection to the selected backend, bidirectionally copying the TCP contents between these two connections.  TLS load balancers additionally terminate the TLS connection, forwarding the plaintext to the backend server (typically inside a new TLS connection).  TLS load balancers must therefore hold the private keys for the domains they serve.

When a TCP load balancer forwards a TLS stream, the load balancer has no way to incorporate additional information into the stream.  Insertion of any additional data would cause the connection to fail.  However, the load-balancer and backend can share additional information if they agree to speak a new protocol.  The most popular protocol used for this purpose is currently the [PROXY protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt), developed by HAPROXY.  This protocol prepends a plaintext collection of metadata (e.g. client IP address) onto the TCP socket.  The backend can parse this metadata, then pass the remainder of the stream to its TLS library.

The PROXY protocol is widely used, but it offers no confidentiality or integrity protection, and therefore might not be suitable when the load balancer and backend communicate over the public internet.


# Goals

*   Enable TCP load balancers to forward metadata to the backend.
*   Reduce the need for TLS-terminating load balancers.
*   Ensure confidentiality and integrity for all forwarded metadata.
*   Enable split ESNI architectures.
*   Prove to the backend that the load balancer intended to associate this metadata with this connection.
*   Achieve good CPU and memory efficiency.
*   Don’t impose additional latency.
*   Support backends that receive a mixture of direct and load-balanced TLS.
*   Support use in QUIC.
*   Enable simple and safe implementation.


# Encoding

This encoding is expressed in the [TLS 1.3 presentation language](https://tools.ietf.org/html/rfc8446#section-3).

A ProxyExtension is identical in form to a standard TLS extension, with a new identifier space for the extension types.
```
struct {
  ProxyExtensionType extension_type;
  opaque extension_data<0..2^16-1>;
} ProxyExtension;
```


The ProxyData contains a set of ProxyExtensions.
```
struct {
  ProxyExtension proxy_data<0..2^16-1>;
} ProxyData;
```



The EncryptedProxyData structure contains metadata associated with the original ClientHello, encrypted with a pre-shared key that is configured out of band.
```
struct {
  opaque psk_identity<1..2^16-1>;
  opaque nonce<8..2^16-1>
  opaque encrypted_proxy_data<1..2^16-1>;
} EncryptedProxyData;
```

psk_identity: The identity of a PSK previously agreed upon by the load balancer and the backend.  Including the PSK identity allows for updating the PSK without disruption.

nonce: Non-repeating initializer for the AEAD.  This prevents an attacker from observing whether the same ClientHello is marked with different metadata over time.

encrypted_proxy_data: AEAD-Encrypt(key, nonce, additional_data=ClientHello, plaintext=ProxyData).  The key and AEAD function are agreed out of band and associated with psk_identity.

When the load balancer receives a ClientHello, it serializes any relevant metadata into a ProxyData, then encrypts it, with the ClientHello as associated data, to produce EncryptedProxyData.


# Defined ProxyExtensions

Like a standard TLS Extension, a ProxyExtension is identified by a 2-byte type number.  There are initially three type numbers allocated:
```
enum {
  padding(0),
  network_address(1),
  esni_inner(2),
  (65535)
} ProxyExtensionType;
```

The “padding” extension functions as described in RFC 7685.  It is used here to avoid leaking information about the other extensions.

The “network_address” extension functions as described in draft-kinnear-tls-client-net-address.  It conveys the client IP address observed by the load balancer.

The “esni_inner” extension can only be used if the ClientHello contains the encrypted_server_name extension.  The extension_data is the ClientESNIInner, which contains the true SNI and nonce.  This is useful when the load balancer knows the ESNI private key and the backend does not, i.e. split mode ESNI.

Load balancers SHOULD only include extensions that are specified for use in ProxyData, and backends MUST ignore any extensions that they do not recognize.


# Use with TLS over TCP

When forwarding a TLS stream over TCP, the load balancer SHOULD send a ProxyHeader at the beginning of the stream:
```
struct {
  uint8 opaque_type = 0;
  ProtocolVersion version = 0;
  uint16 length = length(ProxyHeader.contents);
  EncryptedProxyData contents;
} ProxyHeader;
```

The opaque_type field ensures that this header is distinguishable from an ordinary TLS connection, whose first byte is always 22.  This structure matches the layout of TLSPlaintext with a ContentType of “invalid”, potentially simplifying parsing.

Following the ProxyHeader, the load balancer MUST send the full contents of the TCP stream, exactly as received from the client.  The backend will observe the ProxyHeader, immediately followed by a TLSPlaintext frame containing the ClientHello.  The backend will decrypt the ProxyHeader using the ClientHello as associated data, and process the ClientHello and the remainder of the stream as standard TLS.

When receiving a ProxyHeader with an unrecognized version, the backend SHOULD ignore this ProxyHeader and proceed as if the following byte were the first byte received.


# Use with QUIC

A QUIC load balancer provides this service by extracting the ClientHello from any Initial packet that contains a complete ClientHello.  The load balancer then computes EncryptedProxyData and constructs a new packet consisting of the 4-byte value TBD (a reserved QUIC version number), the EncryptedProxyData, and the entire Initial.

The backend, upon receipt of a packet with QUIC version TBD, reverses this transformation to recover the original Initial packet and extract the proxy data for this connection.


# Configuration
The method of configuring of the PSK on the load balancer and backend is not specified here.  However, the PSK MAY be represented as a ProxyKey:
```
struct {
  ProtocolVersion version = 0;
  opaque psk_identity<1..2^16-1>;
  CipherSuite cipher_suite;
  opaque key<16..2^16-1>
} ProxyKey;
```

# IANA Considerations

Need to create a new ProxyExtensionType registry.

Need to allocate TBD as a reserved QUIC version code.


# Acknowledgements

This is an elaboration of an idea proposed by Eric Rescorla during the development of ESNI.  Thanks to David Schinazi and David Benjamin for suggesting important improvements.


# Open Questions

Should the ProxyExtensionType registry have a reserved range for private extensions?
