"""
NITree

This is a proof of concept implementation for an algorithm that uses Named Identifiers (see RFC 6920 ) to hash a given key-value data structure (e.g. JSON) into a merkle tree like structure can be shared wihtout loosing full fine grained data access control. Publishing this Named Identifiers Tree (root), e.g. on a distributed ledger, can be used to notarize the full data structure. Furthermore, RFC 6920 specifies a URL too query for the data behind the NI. The data owner being querried can then authorise the querying party and reveal parts or all of the data in the NITree. By checking the hashes, the querying party can be sure to receive authentic data.

For further Details see the README.

.. module:: forest
   :synopsis: grows trees

.. moduleauthor:: Sebastian Schmittner <sebastian@schmittner.pw>

Copyright 2020 Sebastian Schmittner

This program is free software: you can redistribute it and/or modify
it under the terms given in the LICENSE file.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE
file for details.

"""

import logging
import hashlib

def _name_string(obj, hash_fct, auth):
    """
    This function computes the name of a string using a (hidden) salt according to https://github.com/Echsecutor/NITree/blob/master/README.md
    """
    if auth and not auth[-1:] == "/"):
        auth += "/"
            
    salty = "ni://" + hash_fct.__name__ + ";" + hash_fct(obj) + "?salt=" + secrets.token_urlsafe()
        
    return "ni://" + auth + hash_fct.__name__ + ";" + hash_fct(salty)


def name(obj, hash_fct = hashlib.sha256, auth = ""):
    """
    Implements the algorithm described in https://github.com/Echsecutor/NITree/blob/master/README.md

    :param obj: the objected to be named
    :type obj: str, list, map

    :param hash_fct: the hashing function to use. hash_fct.__name__ should be the name according to RFC 6920, e.g. 'sha-256'.
    :type hash_sct: function

    :param auth: the authority component, if any.
    :type auth: str

    :rtype: str
    """
    if isinstance(obj,str):
        return _name_string(obj, hash_fct, auth)
           
    if isinstance(obj, list):
        if len(obj) == 0:
            return _name_string("", hash_fct, auth)
        if len(obj) == 1:
            return name(obj[0], hash_fct, auth)
        last = []
        if len(obj) %2 != 0:
            last = obj[-1:]
            obj = obj[:-1]
        name_list = []
        for el in list:
            name_list.append(name(el, hash_fct))
        name_list.sort()

        short_list = []
        for el1,el2 in zip(name_list[0::2], name_list[1::2]):
            short_list.append(el1 + el2)
        if last:
            short_list += last
            
        return name(short_list, hash_fct, auth)

    if isinstance(obj, map):
        lst = []
        for key, cal in obj.items():
            lst.append(name(key, hash_fct) + name(val, hash_fct), hash_fct)
        return name(lst, hash_fct, auth)

    raise TypeError("%s is neither string, nor list, nor map.", obj)
    
