from setuptools import find_packages, setup

setup(
    name="rsaelectie",
    version="0.0.1",
    description="Adapted RSA library for university project called Electie",
    author="tim172021@googlegroups.com",
    license="MIT",
    packages=["rsaelectie"],
    setup_requires=['wheel'],
    install_requires=["pycryptodome", "pydantic"],
)