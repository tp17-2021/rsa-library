from setuptools import find_packages, setup

setup(
    name="rsaelectie",
    packages=find_packages(include=["rsaelectie"]),
    version="0.1",
    description="RSA library for project called Electie",
    author="tim172021@googlegroups.com",
    license="MIT",
    install_requires=["pycryptodome", "pydantic"]
)
