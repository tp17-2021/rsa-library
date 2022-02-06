# RSA Electie library
Adapted RSA library for university project called Electie.

Library is uploaded to PyPI on this [link](https://pypi.org/project/electiersa/).

## How to install library
`pip install electiersa`

## How to use library in project
`import electiersa` or `from electiersa import electiersa`

## Steps to update library
1. Delete all files in the `dist` folder
2. Update the version number in the `setup.py` file`
3. Re-create the wheels with `python3 setup.py sdist`
4. Re-upload the new files with with `twine upload dist/*`