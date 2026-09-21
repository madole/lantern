from lantern import __name__ as package_name


def test_package_imports():
    assert package_name == "lantern"
