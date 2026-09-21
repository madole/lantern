from network_lister import __name__ as package_name


def test_package_imports():
    assert package_name == "network_lister"
