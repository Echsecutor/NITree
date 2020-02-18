# NITree

This Repository is used to develope *Named Identifier Trees (NITrees)*. An NITree is a datastructure which is derived from some *plain text* data object. A protocol to lookup the plaintext data and veryfy its integrity from the NITree is developed alongside the NITree object to make use of the concept.

## General Idea

NITrees make use of Named Identifiers (NIs, see [RFC 6920](https://www.rfc-editor.org/info/rfc6920) ) to hash a given data structure (e.g. in JSON) into a structure of hashes that can be shared wihtout loosing full fine grained data access control. Publishing this Named Identifiers Tree (root), e.g. on a distributed ledger, can be used to notarize the full data structure. RFC 6920 specifies which URL to query for the data behind the NI. The data owner being querried can then authorise the querying party and reveal parts or all of the data in the NITree. By checking the hashes, the querying party can be sure to receive authentic data.


Being more explicit, an NITree has the following defining properties:
- The NITree contains a full comittment to the data object, i.e. given the NITree and the data object, anyone can verify thet the NITree was indeed derived from the data object. Furthermore, the commitment is one-way, i.e. it is not possible to derive the plaintext from the NITree and collissions are minimized, i.e. it is extremely unlikely that two different data objects yield the same NITree.
  - This means, that the NITree contains a cryptographic hash of the plain text.
- The NITree contains all information to derive a URL from which anyone knowing the NITree can `GET` (https) the plain text data. The host may authorise the requesting party and grant or deny access to the plain text at his own descretion. 
  - A NI that includes a domain (authority) has both properties. In fact, such a NI is the simplest form of an NITree.
- The NITree contains structural information about the plain text data. Some of the data may be contained in plain text while only some sensitive parts are conceiled.
- NITrees can be nested in order to implement fine grained access control to different parts of the plain text data.


## Specs

### Data Objects

For simplicity, we consider only the following data types:
- A String is an Object
- An unordered List of Objects is an Object
- An ordered n-tuple (e.g. a pair) of objects is an object
  - In particular, a list of pairs where the first elements of each pair are required to be unique, i.e. a map/dictionary, is an object


This means, that we treat all other data types (integer, floating point numbers, boolean, etc.) as strings. In practice, it is important to have a unique serialization to strings of all such data types.


### NI Roots

A root of an NITree is a named identifier of the form "ni://n-authority/alg;val" where
- "alg" is the name of a hashing algorithm, e.g. "sha-256", see [RFC 6920](https://www.rfc-editor.org/info/rfc6920) for details. We will throughout use sha-256, but of course any other cryptographic hash algorithm may be used in practise.
- "n-authority" is a domain name, e.g. "example.com". n-authority SHOULD be given for the main root in order to allow for data lookup. It MAY be omitted for roots of sub-trees, in which case it is assumed to be the same as for the main root.
- "val" is the hash value of the NITree "below this root"


### Growing NITrees


#### Salted NIs for Strings

A string is converted into a root in two steps. First, compute `ni://alg;val` by applying `alg` to the string to yield `val`.
E.g. "Hello World!" yields 
```
ni://sha-256;03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340
```

To prevent rainbow table/guessing attacks on the hash, the result SHOULD be salted and hashed again as follows:
A random salt is appended as a query parameter according to RFC 6920, e.g.
```
ni://sha-256;03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340?salt=NIPSI2XQLTRCNIUAYBNNWV6K5Q
```
The length (entropy) of the salt can be adapted according to security needs. The resulting salted NI is considered a string and hashed again into the NIroot by again applying `alg`. The example yields:
```
ni://example.com/sha-256;22aada314d02532757013651bf5ca5c5ecd36640c2d47b3470abd9cfadd246da
```

The resulting NITree consists of the resulting root, the intermediate NI and the original string, e.g.
```
(
  "ni://example.com/sha-256;22aada314d02532757013651bf5ca5c5ecd36640c2d47b3470abd9cfadd246da",
  (
    "ni://sha-256;03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340?salt=NIPSI2XQLTRCNIUAYBNNWV6K5Q",
      "Hello World!"
  )
)
```

If the original String already contains enough entropy, e.g. a large random number such as a serial, the salting step MAY be omitted. The Empty String should always be salted or not concealed at all.


#### Combining NIs

To form a Merkle Tree, an operation of hashing a pair of hashes is needed. A simple way of doing so is to concatenate the hashes as strings and hashing the result. For two NIs, "ni://n-authority1/alg1;val1?query1" and "ni://n-authority2/alg2;val2?query2" we define the combined NI "ni://n-authority/alg;val" to be computed by lexikographically sorting val1?query1 < val2?query2 and then applying the hashing algorithm "alg" to the concatenation "val1?query1val2?query2".


#### NIs for Lists

For an unordered list, conmpute the NITree for all elements. The n-authority parts for the elements SHOULD be omitted. If an n-authority is given for one element's NIRoot, it MUST be given for all. The NIRoot of the list is then generated by 
- lexicographic sorting of the elements' NIRoots
- pairwise combining the NIroots to get a list with half (ceil) as many entries (leave the last one alone for odd list size)
- repeat until there is only one NIRoot left
This standard merkle tree conctruction yields the NIRoot of the list. The NITree consists of the full merkle tree.

For Example `["Hello", "World"]` yields the NITree leaves
```
[
  ("ni://sha-256;66a045b452102c59d840ec097d59d9467e13a3f34f6494e539ffd32c1bb35f18", "Hello"),
  ("ni://sha-256;aa1db5c660d3d1f3f4f9361b9848694300929be94b74c84452a87420c59e5df9", "World")
]
```
where salting has been omitted for simplicity in this example, but should be used for similar string values in practise.
The next iteration in this example yields the full NITree
```
(
  ni://sha-256;e6e89c66b353e5ac4046831ac371750d139f871085647a6216c7e080cf5d07f9,
  (
    (
      "ni://sha-256;66a045b452102c59d840ec097d59d9467e13a3f34f6494e539ffd32c1bb35f18",
      "Hello"
    ),
    (
      "ni://sha-256;aa1db5c660d3d1f3f4f9361b9848694300929be94b74c84452a87420c59e5df9",
      "World"
    )
  )
)
```


#### NIs for Maps

The NITree of the map is generated by 
- Compute and combine the NIRoots of the key and value pairs in the map to get a list of strings
- Apply the above algorithm for lists

For example (again omitting hashing), the map
`{"A" : "Hello", "B" : "World"}`
yields the NITree
```
(
  ni://example.com/sha-256;f4d4c5b32bf30934291a2ca6823c7a91a51acd69f438169658612b0e964626a7,
  (
    "ni://sha-256;060ec99b0c06faea8255e0089497945e88853421f61a65f0e8b4abebaddb48a8",
    {
      ("ni://sha-256;06f961b802bc46ee168555f066d28f4f0e9afdf3f88174c1ee6f9de004fc30a0", "A"):
      ("ni://sha-256;66a045b452102c59d840ec097d59d9467e13a3f34f6494e539ffd32c1bb35f18", "Hello")
    }
  ),
  (
    "ni://sha-256;b22abcf4712dbbf546d7e0a6d5dfcdb1939bea205f61d06587e30b38c85171ad",
    {
      ("ni://sha-256;c0cde77fa8fef97d476c10aad3d2d54fcc2f336140d073651c2dcccf1e379fd6", "B"):
      ("ni://sha-256;aa1db5c660d3d1f3f4f9361b9848694300929be94b74c84452a87420c59e5df9", "World")
    }
  )
)
```

## References / Acknowledgment

Ideas for this algorithm are rooted in

- [R. Tröger, S. Clanzett, R. J. Lehmann: Innovative Solution Approach for Controlling Access to Visibility Data in Open Food Supply Chains](http://dx.doi.org/10.18461/pfsd.2018.1817)
- M. Guenther, D. Woerner: ​ SupplyTree - A Federated Systems Approach to solve Supply Chain Traceability
- S. Schmittner: CIRC4Life - Deliverable 5.2 - Development Report and Documentation for Traceability Components and Tools - Data Access Model


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
