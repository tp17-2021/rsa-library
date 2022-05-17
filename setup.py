from setuptools import find_packages, setup

setup(
    name="electiersa",
    version="0.1.1",
    description="Adapted RSA library for university project called Electie",
    author="tim172021@googlegroups.com",
    license="MIT",
    packages=["electiersa"],
    setup_requires=['wheel'],
    install_requires=["pycryptodome", "pydantic"],
)