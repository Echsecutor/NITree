"""
Run the explicit tests from the README examples
"""

from . import ni_forest
import hashlib

NO_SALT_PARAMS = {"hash_fct" : hashlib.sha256, "hash_name" : "sha-256", "authority" : "", "salt_strings":False}


def test_NIs():
    assert ni_forest.hash_string("Hello World!", {"hash_fct" : hashlib.sha256, "hash_name" : "sha-256", "authority" : "example.com"}) == "ni://example.com/sha-256;7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    assert ni_forest.hash_string("Hello World!", {"hash_fct" : hashlib.sha256, "hash_name" : "sha-256", "authority" : ""}) == "ni:///sha-256;7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    assert ni_forest.hash_string("", {"hash_fct" : hashlib.sha256, "hash_name" : "sha-256", "authority" : ""}) == "ni:///sha-256;e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert ni_forest.hash_string("", {"hash_fct" : hashlib.sha256, "hash_name" : "sha-256", "authority" : ""}) == "ni:///sha-256;e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    assert ni_forest.hash_string("Hello World!", {"hash_fct" : hashlib.sha512, "hash_name" : "sha-512", "authority" : ""}) == "ni:///sha-512;861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8"

    
def test_string_no_salt():

    tree = ni_forest.grow("Hello World!", NO_SALT_PARAMS)
    assert "Hello World!" == tree[1]
    assert ni_forest.hash_string("Hello World!", NO_SALT_PARAMS) == tree[0]
    
def test_string_tree():
    test_strings = ["Hello World", "", "öäÜß", "🐣🌠", "\n", " \twhite sp ace\n"]

    for string in test_strings:
        tree = ni_forest.grow(string)
        assert tree[1][1] == string
        assert ni_forest.hash_from_ni(tree[1][0]) == ni_forest.DEFAULT_HASH_FCT(string.encode("utf-8")).hexdigest()
        assert ni_forest.hash_from_ni(tree[0]) == ni_forest.DEFAULT_HASH_FCT(tree[1][0].encode("utf-8")).hexdigest()


def test_list():
    expected = ("ni:///sha-256;3e11ba5abe0b6cede3b05e94baa6974b0f1ebb0f9cb8fbf7702ff8858ba20604",
                [
                    ("ni:///sha-256;185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969", "Hello"),
                    ("ni:///sha-256;78ae647dc5544d227130a0682a51e30bc7777fbb6d8a8f17007463a3ecd1d524", "World")
                ]
    )
    
    actual = ni_forest.grow(["Hello", "World"], NO_SALT_PARAMS)

    assert expected == actual


def test_tuple():
    expected = ("ni:///sha-256;90e76f6a65242adbc4a7f405f2bff524bf7296a5d9ddadb8b9ac6d510d6f06f7",
                (
                    ("ni:///sha-256;78ae647dc5544d227130a0682a51e30bc7777fbb6d8a8f17007463a3ecd1d524", "World"),
                    ("ni:///sha-256;185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969", "Hello")
                )
    )
    actual = ni_forest.grow(("World", "Hello"), NO_SALT_PARAMS)

    assert expected == actual

def test_map():
    mappe = {"Hello" : "World", "a": "B"}
    assert ni_forest.grow(mappe, NO_SALT_PARAMS) == ni_forest.grow(list(mappe.items()), NO_SALT_PARAMS)
