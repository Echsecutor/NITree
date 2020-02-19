"""NITree

This is a proof of concept implementation for an algorithm that uses
Named Identifiers (see RFC 6920 ) to hash a given key-value data
structure (e.g. JSON) into a merkle tree like structure can be shared
wihtout loosing full fine grained data access control. Publishing this
Named Identifiers Tree (root), e.g. on a distributed ledger, can be
used to notarize the full data structure. Furthermore, RFC 6920
specifies a URL too query for the data behind the NI. The data owner
being querried can then authorise the querying party and reveal parts
or all of the data in the NITree. By checking the hashes, the querying
party can be sure to receive authentic data.

This file is part of https://github.com/Echsecutor/NITree/

For further Details see the README.

.. module:: ni_forest
   :synopsis: Grows NITrees

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
import re
import secrets
import collections

DEFAULT_HASH_FCT = hashlib.sha256
DEFAULT_HASH_NAME = "sha-256"

def hash_string(input, params):
    """
    Returns only the NI for the input as a str. Inputs are assumed to be UTF-8 Strings!
    """
    if not isinstance(input, str):
        raise TypeError("Argument input must be of type str, not {type(input)}")

    auth = params["authority"]

    return "ni://" + auth + "/" + params["hash_name"] + ";" + params["hash_fct"](input.encode("utf-8")).hexdigest()


def hash_from_ni(ni):
    match = re.match(r'ni://(?:[^/]+)?/(?:[^;/]+);([^?]+)(?:\?.+)?', ni)
    if not match:
        raise ValueError("%s is not a NI", ni)
    return match.group(1)


def _grow_string(obj, params):
    """
    This function computes the NIRoot and tree of a string using a (hidden) salt according to https://github.com/Echsecutor/NITree/
    """

    if not params["salt_strings"]:
        logging.warning("Not salting string")
        return (hash_string(obj, params), obj)
        
    salty = hash_string(obj, params) + "?salt=" + secrets.token_urlsafe()
        
    return (hash_string(salty, params), (salty, obj))


def grow(obj, params = {"hash_fct" : DEFAULT_HASH_FCT, "hash_name" : DEFAULT_HASH_NAME, "authority" : "", "salt_strings" : True}):
    """
    Implements the algorithm described in https://github.com/Echsecutor/NITree/

    A NIRoot "with all subtrees revealed" is computed from the input obj.

    :param obj: the seed for the tree
    :type obj: str, list, tuple, map

    :param params["hash_fct"]: the hashing function to use. 
    :type params["hash_fct"]: function

    :param params["hash_name"]: The name of the hash function according to RFC 6920, e.g. 'sha-256'.
    :type params["hash_name"]: str

    :param params["authority"]: the authority component for th NI URI
    :type params["authority"]: str

    :rtype: (str, obj)
    """
    if isinstance(obj, str):
        return _grow_string(obj, params)
           
    if isinstance(obj, list) or isinstance(obj, tuple):
        if len(obj) == 0:
            # The NIRoot of an empty list/tuple is the same as for an empty string
            empty = _grow_string("", params)
            return (empty[0], (empty[1][0], obj))

        tree = []
        for element in obj:
            tree.append(grow(element, params))
        if isinstance(obj, list):
            tree.sort()
        else:
            tree = tuple(tree)
            
        concat = ""
        for root in tree:
            concat += root[0]
        return (hash_string(concat, params), tree)

    if isinstance(obj, collections.abc.Mapping):
        return grow(list(obj.items()), params)

    raise TypeError("{obj} is neither str, nor list, nor tuple, nor map.")
    
