# NITree

This Repository is used to develop *Named Identifier Trees
(NITrees)*. An NITree is a data structure which is derived from some
*plain text* data object. A protocol to lookup the plain text data and
verify its integrity from the NITree is developed alongside the NITree
object definition in order to make the concept usable.

## General Idea

NITrees make use of Named Identifiers (NIs, see [RFC
6920](https://www.rfc-editor.org/info/rfc6920) ) to hash a given data
structure (e.g. in JSON) into a structure of hashes that can be shared
without loosing fine grained data access control. Publishing this
Named Identifier Tree root, e.g. on a distributed ledger, can be
used to notarize the full data structure. RFC 6920 specifies which URL
to query for the data behind the NI. The data owner being queried can
then authorize the querying party and reveal parts or all of the data
in the NITree. By checking the hashes, the querying party can be sure
to receive authentic data.


Being more explicit, an NITree has the following defining properties:
- The NITree contains a full commitment to the data object, i.e. given the NITree root and the data object, anyone can verify that the NITree was indeed derived from the data object. Furthermore, the commitment is one-way, i.e. it is not possible to derive the plain text from the NITree. Collisions are minimized, i.e. it is extremely unlikely that two different data objects yield the same NITree.
  - This means, that the NITree contains a cryptography hash of the plain text data.
- The NITree root contains all information to derive a URL from which one can `GET` (https) the plain text data. The host may authorize the requesting party and grant or deny access to the plain text at his own discretion. 
  - A NI that includes a domain (authority) has both properties. In fact, such a NI is the simplest form of an NITree consisting only of a root.
- The NITree contains structural information about the plain text data. Some of the data may be contained in plain text while only some sensitive parts are concealed.
- NITrees can be nested in order to implement fine grained access control to different parts of the plain text data.
- It is possible to reveal only parts of the structure and plain text data and still being able to verify that this data is authentic following the general Merkle tree idea when building the NITree.


## Specs

### Data Objects

For simplicity, we consider only the following data types:
- A String is an Object
- An unordered List of Objects is an Object
- An ordered n-tuple (e.g. a pair) of objects is an object
  - In particular, a list of pairs where the first elements of each pair are required to be unique, i.e. a map/dictionary, is an object


This means, that we treat all other data types (integer, floating
point numbers, boolean, etc.) as strings. In practice, it is important
to have a unique serialization to strings of all such data
types. (E.g. dis ambiguities between "False" / "false" / "0" / "" / "None" / ... need to be avoided.)


### NI Roots

A root of an NITree is a named identifier of the form `ni://authority/alg;val?query-string` where
- `alg` is the name of a hashing algorithm, e.g. `sha-256`, see [RFC 6920](https://www.rfc-editor.org/info/rfc6920) for details. We will
  throughout use `sha-256`, but of course any other cryptography hash
  algorithm may be used in practice.
- `authority` is a domain name, e.g. `example.com`. `authority` SHOULD
  be given for the main root in order to allow for data lookup. It MAY
  be omitted for roots of sub-trees, in which case it is assumed to be
  the same as for the main root.
- `val` is the hash value of the NITree "growing from this root".
- The `?query-string` is optional. If given, the `query-string` is a
  `&` separated `key=value` list as used with HTTP URLs, see
  [RFC2616](https://www.rfc-editor.org/rfc/rfc2616).

#### Lookup

According to RFC 6920, the tree below the root `ni://authority/alg;val?query-string` can be `GET` queried at https://authority/.well-known/ni/alg/val?query-string . The corresponding http:// URL SHOULD redirect to http**s** but the client SHOULD query https directly. If authorization is required, the host MUST enforce TLS or reject the communication.
The queried host SHOULD answer with one of the following status codes:
- `200 OK` and the body containing the tree that grows from the root
- `401 Unauthorized` in order to indicate that the requesting party needs to be authorized in order to get access.
- `403 Forbidden` in order to indicate that authorization was successful but the host denies to reveal further information to the requesting party.
- `404 Not Found` in order to indicate that the host does not know the tree growing form this root.


### Revealing Trees

Wherever a root is expected, the pair of the root and its tree may be
used instead. This saves one lookup in cases where no additional
authorization/permission checks are required, i.e. if anyone with
access to the root is also allowed to access the tree, the two can be
directly send as a pair. For upstream hashing, the pair of root and
tree is considered as if only the root string was given.


### Growing NITrees


#### Trees for Strings

A string is converted into a root in two steps. First, compute `ni:///alg;val` by applying `alg` to the string to yield `val`. This yields the root of the tree consisting only of the original string.
E.g. "Hello World!" yields 
```
("ni:///sha-256;7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069", "Hello World!")
```
where we denote the tree and its root as a pair.
If the original String already contains enough entropy, e.g. a large random number such as a serial, the following salting step MAY be omitted and the above be used as the tree and root.


To prevent rainbow table/guessing attacks on the hash, the result SHOULD be salted and hashed again as follows:
A random salt is appended as a query parameter, e.g.
```
ni:///sha-256;7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069?salt=NIPSI2XQLTRCNIUAYBNNWV6K5Q
```
The length (entropy) of the salt can be adapted according to security needs. The resulting salted NI is considered a string and hashed again into the NIroot by again applying `alg`. The example yields:
```
ni://example.com/sha-256;9a9c0e29eddafd03f046865ea8369777544ff6bff251f9d61f5fe9311a8ffede
```

The resulting NITree (revealing all sub trees) is
```
(
  "ni://example.com/sha-256;9a9c0e29eddafd03f046865ea8369777544ff6bff251f9d61f5fe9311a8ffede",
  (
    "ni:///sha-256;7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069?salt=NIPSI2XQLTRCNIUAYBNNWV6K5Q",
      "Hello World!"
  )
)
```

In a typical use case,
```
ni://example.com/sha-256;9a9c0e29eddafd03f046865ea8369777544ff6bff251f9d61f5fe9311a8ffede
```
would be published. If access is granted to an authorized query to
http://example.com/.well-known/ni/sha-256/9a9c0e29eddafd03f046865ea8369777544ff6bff251f9d61f5fe9311a8ffede
, the host would typically answer with
```
(
  "ni:///sha-256;7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069?salt=NIPSI2XQLTRCNIUAYBNNWV6K5Q",
  "Hello World!"
)
```
from where the querying party can verify the data integrity.



#### Trees for Lists

For an unordered list, compute the NITree for all elements. The
authority parts for the elements MAY be omitted. If an authority is
given for one element's NIRoot, it MUST be given for all. This yields
a list of NIRoot-strings which is the NITree os the list. The NIRoot
of is then generated by
- lexicographic sorting and
- concatenation of the elements' roots
- applying `alg` to the resulting string


For Example `["Hello", "World"]` yields the NITree
```
[
"ni:///sha-256;185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969",
"ni:///sha-256;78ae647dc5544d227130a0682a51e30bc7777fbb6d8a8f17007463a3ecd1d524"
]
```
where salting has been omitted for simplicity in this example, but should be used for similar string values in practice. The root of this tree is
```
ni://example.com/sha-256;3e11ba5abe0b6cede3b05e94baa6974b0f1ebb0f9cb8fbf7702ff8858ba20604
```



#### Trees for Tuples

Replacing each element of the tuple by its NIRoot yields the NITree for the tuple. The root is obtained by concatenating the element root strings in the given order and applying `alg`.

For example `("World", "Hello")` yields the NIRoot (all sub trees revealed)
```
("ni://example.com/sha-256;90e76f6a65242adbc4a7f405f2bff524bf7296a5d9ddadb8b9ac6d510d6f06f7",
    (
        ("ni:///sha-256;78ae647dc5544d227130a0682a51e30bc7777fbb6d8a8f17007463a3ecd1d524", "World"),
        ("ni:///sha-256;185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969", "Hello")
    )
)
```



## References / Acknowledgment

Ideas for this algorithm are rooted in

- [R. Tröger, S. Clanzett, R. J. Lehmann: Innovative Solution Approach for Controlling Access to Visibility Data in Open Food Supply Chains](http://dx.doi.org/10.18461/pfsd.2018.1817)
- M. Guenther, D. Woerner: ​ SupplyTree - A Federated Systems Approach to solve Supply Chain Traceability
- S. Schmittner: CIRC4Life - Deliverable 5.2 - Development Report and Documentation for Traceability Components and Tools - Data Access Model

An Algorithm with a more specific scope and a subset of the features of NITrees is developed in parallel at
- https://github.com/RalphTro/epcis-event-hash-generator


## License

Copyright 2020 Sebastian Schmittner <sebastian@schmittner.pw>

<a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-sa/4.0/88x31.png" /></a><br />The algorithm description, documentation and other text documents in this work are licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/">Creative Commons Attribution-ShareAlike 4.0 International License</a>. You may use/adapt them as long as you share it under the same license and name "Sebastian Schmittner" as the original author.

<a href="https://www.gnu.org/licenses/gpl-3.0.html">
<img alt="GPLV3" style="border-width:0" src="http://www.gnu.org/graphics/gplv3-127x51.png" /><br />

All code published in this repository is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
</a>

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
